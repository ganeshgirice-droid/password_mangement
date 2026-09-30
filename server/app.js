import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { openDatabase } from "./database.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, "..", "public");
const MAX_CIPHERTEXT = 64_000;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

function validBlob(value, limit = MAX_CIPHERTEXT) {
  return typeof value === "string" && value.length > 0 && value.length <= limit && B64.test(value);
}

export async function createApp({ dbPath = path.join(here, "..", "data", "vault.sqlite") } = {}) {
  const store = await openDatabase(dbPath);
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
  });
  app.use(express.json({ limit: "100kb" }));

  app.get("/api/health", (_req, res) => res.json({ ok: true, database: "sqlite", localOnly: true }));

  app.get("/api/vault", (_req, res) => {
    const row = store.all("SELECT kdf_salt AS salt, verifier_iv AS verifierIv, verifier_ciphertext AS verifierCiphertext FROM vault_meta WHERE id = 1")[0];
    res.json(row ? { exists: true, ...row } : { exists: false });
  });

  app.post("/api/vault/setup", (req, res) => {
    const { salt, verifierIv, verifierCiphertext } = req.body ?? {};
    if (!validBlob(salt, 128) || !validBlob(verifierIv, 64) || !validBlob(verifierCiphertext, 512)) {
      return res.status(400).json({ error: "Vault setup data is invalid." });
    }
    if (store.all("SELECT id FROM vault_meta WHERE id = 1").length) {
      return res.status(409).json({ error: "A vault has already been created on this computer." });
    }
    store.run("INSERT INTO vault_meta (id, kdf_salt, verifier_iv, verifier_ciphertext) VALUES (1, ?, ?, ?)", [salt, verifierIv, verifierCiphertext]);
    return res.status(201).json({ ok: true });
  });

  app.get("/api/items", (_req, res) => {
    const rows = store.all("SELECT id, iv, ciphertext, created_at AS createdAt, updated_at AS updatedAt FROM credentials ORDER BY updated_at DESC");
    res.json(rows);
  });

  app.post("/api/items", (req, res) => {
    const { iv, ciphertext } = req.body ?? {};
    if (!validBlob(iv, 64) || !validBlob(ciphertext)) return res.status(400).json({ error: "Encrypted credential data is invalid." });
    const id = randomUUID();
    const now = new Date().toISOString();
    store.run("INSERT INTO credentials (id, iv, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", [id, iv, ciphertext, now, now]);
    return res.status(201).json({ id, iv, ciphertext, createdAt: now, updatedAt: now });
  });

  app.put("/api/items/:id", (req, res) => {
    const { iv, ciphertext } = req.body ?? {};
    if (!validBlob(iv, 64) || !validBlob(ciphertext)) return res.status(400).json({ error: "Encrypted credential data is invalid." });
    const existing = store.all("SELECT created_at AS createdAt FROM credentials WHERE id = ?", [req.params.id])[0];
    if (!existing) return res.status(404).json({ error: "Credential not found." });
    const now = new Date().toISOString();
    store.run("UPDATE credentials SET iv = ?, ciphertext = ?, updated_at = ? WHERE id = ?", [iv, ciphertext, now, req.params.id]);
    return res.json({ id: req.params.id, iv, ciphertext, createdAt: existing.createdAt, updatedAt: now });
  });

  app.delete("/api/items/:id", (req, res) => {
    const existing = store.all("SELECT id FROM credentials WHERE id = ?", [req.params.id])[0];
    if (!existing) return res.status(404).json({ error: "Credential not found." });
    store.run("DELETE FROM credentials WHERE id = ?", [req.params.id]);
    return res.status(204).end();
  });

  app.use(express.static(publicDir, { etag: true }));
  app.get("*", (_req, res) => res.sendFile(path.join(publicDir, "index.html")));
  app.use((err, _req, res, _next) => {
    if (err?.type === "entity.too.large") return res.status(413).json({ error: "Request is too large." });
    console.error("Request failed:", err?.message ?? err);
    return res.status(500).json({ error: "The request could not be completed." });
  });

  app.locals.closeDatabase = () => store.close();
  return app;
}
