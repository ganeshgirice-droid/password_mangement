# VaultDB — Password Manager DBMS Mini Project

## Abstract
VaultDB is a local-first, single-user password-vault demonstration built to explain database-backed CRUD operations and relational design. Credential details are encrypted in the browser before the Express API stores them in a local SQLite database. The project is intended for classroom demonstration with dummy data, not for production password storage.

## Objectives
- Demonstrate a relational schema with primary keys, constraints, and an index.
- Implement Create, Read, Update, and Delete (CRUD) operations through an API.
- Persist records in SQLite so they survive application restarts.
- Demonstrate filtering/search, password generation, strength feedback, and explicit reveal/copy actions.
- Keep credential plaintext and the derived encryption key out of the database and API payloads.

## Technology stack
| Layer | Technology | Responsibility |
| --- | --- | --- |
| Browser | HTML, CSS, JavaScript, Web Crypto API | UI, PBKDF2 key derivation, AES-GCM encryption/decryption |
| Application | Node.js, Express | Local API, input validation, serving static assets |
| Database | SQLite through SQL.js | Durable local relational database file |

## Relational schema
### `vault_meta`
One singleton row (`id = 1`) stores a random PBKDF2 salt and an AES-GCM encrypted known-value verifier. The master password itself is not stored. The database check constraint limits the table to one vault record.

### `credentials`
Each row uses a UUID primary key. `iv` stores the unique AES-GCM nonce for that row, and `ciphertext` contains the encrypted JSON record. `created_at` and `updated_at` are ISO timestamps. An index on `updated_at DESC` supports newest-first listing.

The encrypted JSON contains `site`, `username`, `password`, `url`, `category`, and `notes`; the database cannot search the plaintext fields. The browser downloads ciphertext and performs search after local decryption.

## Relationships / ER model
`vault_meta` is a singleton parent for the local vault; the logical relationship is one vault to many credentials. The implementation uses the singleton vault constraint rather than repeating `vault_id` on every credential row because there is only one local vault per database file.

## Data flow
1. On first use, the browser generates a random salt and derives an AES-256 key from the master password with PBKDF2-SHA-256 (310,000 iterations).
2. The browser encrypts a known-value verifier and sends only the salt, verifier nonce, and verifier ciphertext to the local API.
3. When a credential is saved or updated, the browser JSON-serializes the fields and encrypts them with AES-GCM and a fresh random 96-bit IV.
4. Express validates the encrypted payload shape and writes only UUID, IV, ciphertext, and timestamps into SQLite.
5. On unlock, the browser derives the key again and decrypts the verifier. It fetches ciphertext and decrypts records locally in memory.
6. Locking clears the in-memory key and decrypted records from application state. Refreshing the page returns to the locked screen.

## Functional requirements
- Create, list, edit, and delete encrypted records.
- Search by service, username, URL, or category after decryption in the browser.
- Filter by category.
- Generate a random password and view a qualitative strength indicator.
- Reveal or copy sensitive values only after the user explicitly requests it.
- Explain schema, data flow, objectives, and limitations inside the website.

## How to run
1. Install Node.js 20 or newer.
2. Open the extracted `vaultdb-vscode` folder in VS Code.
3. Open Terminal → New Terminal and run `npm install`.
4. Run `npm run dev`.
5. Open `http://127.0.0.1:4170` in a browser.
6. Create a master password (8 characters minimum) and use dummy test data.
7. Run `npm test` for the local API/database smoke tests.

The SQLite file is created automatically at `data/vault.sqlite` after startup. To reset the demo, stop the server and delete that file; doing so permanently removes the local vault.

## Limitations and responsible use
This is a teaching prototype, not a security-audited product. It has no user accounts, remote sync, authenticated multi-user API, secure backup/recovery, threat-model review, or independent cryptographic audit. The Express service binds to `127.0.0.1` by default and should not be exposed publicly. A person who can run or alter local code on the computer may interfere with the application. Use dummy credentials only; never use this demo as your real password manager.
