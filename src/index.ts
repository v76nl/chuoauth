import "dotenv/config";
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createGoogleClient } from "./services/google.js";
import { createKeyStore } from "./services/token.js";

const config = loadConfig();
const keyStore = await createKeyStore(config.jwt);
const googleClient = createGoogleClient(config.google);
const app = createApp({ config, keyStore, googleClient });

const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`chuoauth listening on http://localhost:${info.port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
        server.close(() => process.exit(0));
    });
}
