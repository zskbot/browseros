import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { GatewayState } from "../src/index.ts";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const encoder = new TextEncoder();
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const sha256 = async (value) => b64url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
const signed = async (privateKey, message) => b64url(await crypto.subtle.sign("Ed25519", privateKey, encoder.encode(message)));

class MemoryStorage {
  values = new Map();
  tail = Promise.resolve();
  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async delete(key) { return this.values.delete(key); }
  async transaction(callback) {
    let release;
    const previous = this.tail;
    this.tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await callback(this);
    } finally {
      release();
    }
  }
}

function createGateway() {
  const storage = new MemoryStorage();
  const env = {
    GATEWAY_ISSUER: "https://gateway.example",
    BROWSEROS_MCP_ORIGIN: "https://desktop.example",
    ALLOWED_TOOL_NAMES: "[]",
    TOKEN_SIGNING_KEY: "test-only-signing-key-that-is-long-enough-for-ci-123456",
    CF_ACCESS_CLIENT_ID: "test-access-id",
    CF_ACCESS_CLIENT_SECRET: "test-access-secret"
  };
  return { gateway: new GatewayState({ storage }, env), storage };
}

const request = (path, method, body, headers = {}) => new Request("https://gateway.example" + path, {
  method,
  headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.10", ...headers },
  body: body === undefined ? undefined : JSON.stringify(body)
});

test("Ed25519 pairing proof gates status and revocation is atomic", async () => {
  const { gateway } = createGateway();
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = b64url(await crypto.subtle.exportKey("raw", keys.publicKey));
  const startResponse = await gateway.fetch(request("/pair/start", "POST", { public_key: publicKey, label: "test desktop" }));
  assert.equal(startResponse.status, 201);
  const started = await startResponse.json();

  let timestamp = Math.floor(Date.now() / 1000);
  const statusMessage = ["browseros-pair-v1", "status", started.transaction_id, started.challenge, String(timestamp)].join("\n");
  const invalidStatus = await gateway.fetch(request("/pair/status", "POST", {
    transaction_id: started.transaction_id, timestamp, signature: b64url(new Uint8Array(64))
  }));
  assert.equal(invalidStatus.status, 401);

  const validStatus = await gateway.fetch(request("/pair/status", "POST", {
    transaction_id: started.transaction_id, timestamp, signature: await signed(keys.privateKey, statusMessage)
  }));
  assert.equal(validStatus.status, 200);
  assert.equal((await validStatus.json()).state, "pending");

  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = await sha256(verifier);
  const redirectUri = "https://client.example/callback";
  const registration = await gateway.fetch(request("/register", "POST", { redirect_uris: [redirectUri] }));
  assert.equal(registration.status, 201);
  const client = await registration.json();
  const authorizeUrl = new URL("https://gateway.example/authorize");
  authorizeUrl.searchParams.set("client_id", client.client_id);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("state", "csrf-state");
  authorizeUrl.searchParams.set("code_challenge", challenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  const authorizePage = await gateway.fetch(new Request(authorizeUrl));
  assert.equal(authorizePage.status, 200);
  const html = await authorizePage.text();
  const transaction = html.match(/name="transaction" value="([^"]+)"/)?.[1];
  assert.ok(transaction);

  const form = new URLSearchParams({ transaction, pairing_code: started.pairing_code, approve: "yes" });
  const approval = await gateway.fetch(new Request("https://gateway.example/authorize", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "192.0.2.11" }, body: form
  }));
  assert.equal(approval.status, 302);
  const redirect = new URL(approval.headers.get("location"));
  const authCode = redirect.searchParams.get("code");
  assert.ok(authCode);
  assert.equal(redirect.searchParams.get("state"), "csrf-state");

  const pairedTimestamp = Math.floor(Date.now() / 1000);
  const pairedMessage = ["browseros-pair-v1", "status", started.transaction_id, started.challenge, String(pairedTimestamp)].join("\n");
  const pairedStatus = await gateway.fetch(request("/pair/status", "POST", {
    transaction_id: started.transaction_id, timestamp: pairedTimestamp, signature: await signed(keys.privateKey, pairedMessage)
  }));
  assert.equal((await pairedStatus.json()).state, "paired");

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code", client_id: client.client_id, code: authCode,
    redirect_uri: redirectUri, code_verifier: verifier
  });
  const tokenRequest = () => new Request("https://gateway.example/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "192.0.2.12" }, body: tokenBody
  });
  const tokenResults = await Promise.all([gateway.fetch(tokenRequest()), gateway.fetch(tokenRequest())]);
  assert.deepEqual(tokenResults.map((response) => response.status).sort(), [200, 400]);

  timestamp = Math.floor(Date.now() / 1000);
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(18)));
  const revokeMessage = ["browseros-pair-v1", "revoke", started.device_id, nonce, String(timestamp)].join("\n");
  const revokeBody = { device_id: started.device_id, nonce, timestamp, signature: await signed(keys.privateKey, revokeMessage) };
  const revokeResults = await Promise.all([
    gateway.fetch(request("/pair/revoke", "POST", revokeBody)),
    gateway.fetch(request("/pair/revoke", "POST", revokeBody))
  ]);
  assert.ok(revokeResults.every((response) => response.status === 200));
  assert.ok((await Promise.all(revokeResults.map((response) => response.json()))).every((body) => body.revoked === true));

  const revokedTimestamp = Math.floor(Date.now() / 1000);
  const revokedMessage = ["browseros-pair-v1", "status", started.transaction_id, started.challenge, String(revokedTimestamp)].join("\n");
  const revokedStatus = await gateway.fetch(request("/pair/status", "POST", {
    transaction_id: started.transaction_id, timestamp: revokedTimestamp, signature: await signed(keys.privateKey, revokedMessage)
  }));
  assert.equal(revokedStatus.status, 403);
});

test("pairing codes are single-use after approval", async () => {
  const { gateway } = createGateway();
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = b64url(await crypto.subtle.exportKey("raw", keys.publicKey));
  const start = await (await gateway.fetch(request("/pair/start", "POST", { public_key: publicKey }))).json();
  assert.match(start.pairing_code, /^[A-HJ-NP-Z2-9]{16}$/);
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const authorizeUrl = new URL("https://gateway.example/authorize");
  const registration = await (await gateway.fetch(request("/register", "POST", { redirect_uris: ["https://client.example/cb"] }))).json();
  authorizeUrl.searchParams.set("client_id", registration.client_id);
  authorizeUrl.searchParams.set("redirect_uri", "https://client.example/cb");
  authorizeUrl.searchParams.set("state", "state");
  authorizeUrl.searchParams.set("code_challenge", await sha256(verifier));
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  const page = await (await gateway.fetch(new Request(authorizeUrl))).text();
  const transaction = page.match(/name="transaction" value="([^"]+)"/)?.[1];
  const form = new URLSearchParams({ transaction, pairing_code: start.pairing_code, approve: "yes" });
  const approved = () => gateway.fetch(new Request("https://gateway.example/authorize", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "192.0.2.20" }, body: form
  }));
  assert.equal((await approved()).status, 302);
  assert.equal((await approved()).status, 400);
});
