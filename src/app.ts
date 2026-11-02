import type { OAuth2Client } from "google-auth-library";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import type { Config } from "./config.js";
import { apiRoutes } from "./routes/api.js";
import { authRoutes } from "./routes/auth.js";
import { wellKnownRoutes } from "./routes/well-known.js";
import type { KeyStore } from "./services/token.js";

export type AppDeps = {
    config: Config;
    keyStore: KeyStore;
    googleClient: OAuth2Client;
};

export function createApp(deps: AppDeps): Hono {
    const app = new Hono();

    // /api/verify はリダイレクト先として許可されたクライアントのオリジンからのみ受け付ける
    const allowedOrigins = [
        ...new Set(
            deps.config.allowedRedirectUris.map((uri) => new URL(uri).origin)
        )
    ];

    if (deps.config.nodeEnv !== "test") {
        // 標準の logger はクエリ文字列 (認可コード等) も出力するため、パスのみ記録する
        app.use(async (c, next) => {
            const start = Date.now();
            await next();
            console.log(
                `${c.req.method} ${c.req.path} ${c.res.status} ${Date.now() - start}ms`
            );
        });
    }
    app.use(secureHeaders());
    app.use("/api/*", cors({ origin: allowedOrigins }));
    app.use("/.well-known/*", cors({ origin: "*" }));

    app.get("/health", (c) => c.json({ status: "ok" }));
    app.route("/auth", authRoutes(deps));
    app.route("/api", apiRoutes(deps));
    app.route("/.well-known", wellKnownRoutes(deps));

    app.notFound((c) => c.json({ error: "not_found" }, 404));
    app.onError((err, c) => {
        console.error(err);
        return c.json({ error: "server_error" }, 500);
    });

    return app;
}
