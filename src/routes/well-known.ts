import { Hono } from "hono";
import type { AppDeps } from "../app.js";
import { getJwks } from "../services/token.js";

export function wellKnownRoutes(deps: AppDeps): Hono {
    const app = new Hono();

    app.get("/jwks.json", (c) => {
        c.header("Cache-Control", "public, max-age=3600");
        return c.json(getJwks(deps.keyStore));
    });

    return app;
}
