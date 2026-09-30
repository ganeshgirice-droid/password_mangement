-- VaultDB mini-project schema (SQLite)
-- Sensitive credential fields are AES-GCM ciphertext produced in the browser.
CREATE TABLE vault_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  kdf_salt TEXT NOT NULL,
  verifier_iv TEXT NOT NULL,
  verifier_ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_credentials_updated_at ON credentials(updated_at DESC);
