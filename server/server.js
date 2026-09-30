import { createApp } from "./app.js";
import { fileURLToPath } from "node:url";

const app = await createApp({
  dbPath: process.env.DB_PATH || fileURLToPath(new URL("../data/vault.sqlite", import.meta.url)),
});
const port = Number(process.env.PORT || 4170);
const host = process.env.HOST || "127.0.0.1";
const server = app.listen(port, host, () => {
  console.log(`VaultDB is running at http://${host}:${port}`);
  console.log("Local-only demo: do not expose this server to the internet.");
});

function shutdown() {
  server.close(() => {
    app.locals.closeDatabase();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
