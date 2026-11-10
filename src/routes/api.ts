import { Hono } from "hono";
import type { AppDeps } from "../app.js";
import { GoogleAuthError, verifyGoogleIdToken } from "../services/google.js";
import { issueToken } from "../services/token.js";
import { verifyRequestSchema, type VerifyResponse } from "../types/index.js";

export function apiRoutes(deps: AppDeps): Hono {
    const { config } = deps;
    const app = new Hono();

    app.post("/verify", async (c) => {
        const body: unknown = await c.req.json().catch(() => null);
        const parsed = verifyRequestSchema.safeParse(body);
        if (!parsed.success) {
            return c.json(
                {
                    error: "invalid_request",
                    error_description: "id_token is required"
                },
                400
            );
        }

        try {
            const googleUser = await verifyGoogleIdToken(
                deps.googleClient,
                parsed.data.id_token,
                {
                    clientId: config.google.clientId,
                    allowedDomain: config.allowedDomain
                }
            );
            const token = await issueToken(deps.keyStore, googleUser, {
                issuer: config.tokenIssuer,
                audience: config.tokenAudience
            });
            return c.json<VerifyResponse>({
                token,
                user: {
                    email: googleUser.email,
                    domain: googleUser.domain
                }
            });
        } catch (err) {
            if (err instanceof GoogleAuthError) {
                return c.json(
                    { error: "invalid_token", error_description: err.code },
                    401
                );
            }
            throw err;
        }
    });

    return app;
}
