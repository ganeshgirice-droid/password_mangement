# VaultDB — Password Manager DBMS Mini Project

A complete, local-only password manager demo you can open in VS Code. It uses **Node.js + Express + SQLite (SQL.js)** and encrypts credential fields in the browser before saving them.

## Run it in VS Code
1. Install **Node.js 20+**.
2. Extract this folder and open it in VS Code.
3. In **Terminal → New Terminal**, run:
   ```bash
   npm install
   npm run dev
   ```
4. Open **http://127.0.0.1:4170**.
5. Create a master password (minimum 8 characters). Use dummy credentials for your demo.

Press `Ctrl+C` in the terminal to stop it. You can also run **VaultDB: Start local app** from the VS Code Run Task menu. Use `npm test` to run API/database smoke tests.

## Features
- Create, view, edit, search, filter, and delete saved logins.
- Generate a strong random password and see strength feedback.
- Reveal/copy username and password only on request.
- Browser-side PBKDF2-SHA-256 key derivation and AES-256-GCM encryption.
- Local SQLite file at `data/vault.sqlite`.
- Built-in DBMS project overview, schema, ER model, and data-flow notes.

## Database design
- `vault_meta`: single vault salt and encrypted verifier.
- `credentials`: UUID primary key, AES-GCM IV, encrypted JSON ciphertext, created/updated timestamps.
- Index: `credentials(updated_at DESC)`.

The exact DDL is in [`db/schema.sql`](db/schema.sql); the report is in [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md).

## Contributing
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, testing, and pull request guidelines.

## Security note
**Educational project only—not a security-audited password manager.** The database stores encrypted records but the API is intentionally a local, single-user teaching example without user authentication or remote access controls. Keep the server bound to localhost, do not expose it to the internet, and use dummy credentials only. The master password is never saved; if forgotten, the encrypted vault cannot be recovered.
