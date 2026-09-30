import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import initSqlJs from "sql.js";

const require = createRequire(import.meta.url);
const schema = `
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf_salt TEXT NOT NULL,
    verifier_iv TEXT NOT NULL,
    verifier_ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_credentials_updated_at ON credentials(updated_at DESC);
`;

export async function openDatabase(dbPath) {
  const SQL = await initSqlJs({
    locateFile: (file) => path.join(path.dirname(require.resolve("sql.js")), file),
  });
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = fs.existsSync(dbPath)
    ? new SQL.Database(new Uint8Array(fs.readFileSync(dbPath)))
    : new SQL.Database();
  db.exec(schema);
  const persist = () => fs.writeFileSync(dbPath, Buffer.from(db.export()));
  persist();

  function all(sql, values = []) {
    const statement = db.prepare(sql);
    try {
      statement.bind(values);
      const rows = [];
      while (statement.step()) rows.push(statement.getAsObject());
      return rows;
    } finally {
      statement.free();
    }
  }

  function run(sql, values = []) {
    db.run(sql, values);
    persist();
  }

  return {
    all,
    run,
    close() {
      persist();
      db.close();
    },
  };
}
