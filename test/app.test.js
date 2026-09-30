import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../server/app.js";

const b64 = (text) => Buffer.from(text).toString("base64");

test("local vault API stores opaque ciphertext and supports CRUD", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultdb-test-"));
  const dbPath = path.join(dir, "test.sqlite");
  const app = await createApp({ dbPath });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (url, options = {}) => fetch(`${base}${url}`, { ...options, headers: { ...(options.body ? { "content-type": "application/json" } : {}), ...options.headers } });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    app.locals.closeDatabase();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const health = await request("/api/health");
  assert.equal(health.status, 200);
  assert.equal((await health.json()).database, "sqlite");

  assert.deepEqual(await (await request("/api/vault")).json(), { exists: false });
  const setup = await request("/api/vault/setup", { method: "POST", body: JSON.stringify({ salt: b64("salt-1234567890"), verifierIv: b64("123456789012"), verifierCiphertext: b64("encrypted-verifier") }) });
  assert.equal(setup.status, 201);
  assert.equal((await request("/api/vault/setup", { method: "POST", body: JSON.stringify({ salt: b64("salt-1234567890"), verifierIv: b64("123456789012"), verifierCiphertext: b64("another") }) })).status, 409);

  const encrypted = { iv: b64("123456789012"), ciphertext: b64("opaque-ciphertext-not-plaintext") };
  const createdResponse = await request("/api/items", { method: "POST", body: JSON.stringify(encrypted) });
  assert.equal(createdResponse.status, 201);
  const created = await createdResponse.json();
  assert.equal(created.ciphertext, encrypted.ciphertext);
  let list = await (await request("/api/items")).json();
  assert.equal(list.length, 1);
  assert.equal(list[0].ciphertext, encrypted.ciphertext);

  const updated = await request(`/api/items/${created.id}`, { method: "PUT", body: JSON.stringify({ ...encrypted, ciphertext: b64("updated-ciphertext") }) });
  assert.equal(updated.status, 200);
  assert.equal((await updated.json()).ciphertext, b64("updated-ciphertext"));
  assert.equal((await request(`/api/items/${created.id}`, { method: "DELETE" })).status, 204);
  assert.deepEqual(await (await request("/api/items")).json(), []);
  assert.ok(fs.existsSync(dbPath), "SQLite file is persisted to disk");
});

test("API rejects malformed encrypted payloads", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultdb-test-"));
  const app = await createApp({ dbPath: path.join(dir, "test.sqlite") });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); app.locals.closeDatabase(); fs.rmSync(dir, { recursive: true, force: true }); });
  const response = await fetch(`${base}/api/items`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ iv: "not base64!", ciphertext: "" }) });
  assert.equal(response.status, 400);
});
