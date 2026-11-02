import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppDeps } from "../app.js";
import {
    FLOW_STATE_TTL_SECONDS,
    openFlowState,
    randomToken,
    sealFlowState,
    type FlowState
} from "../services/flow-state.js";
import {
    createAuthorizationUrl,
    exchangeCodeForIdToken,
    GoogleAuthError,
    verifyGoogleIdToken
} from "../services/google.js";
import { extractStudentId } from "../services/student-id.js";
import { issueToken } from "../services/token.js";
import { callbackQuerySchema, loginQuerySchema } from "../types/index.js";

const FLOW_COOKIE = "chuoauth_flow";
const COOKIE_PATH = "/auth/google";

function buildClientRedirect(
    flow: FlowState,
    params: Record<string, string>
): string {
    const url = new URL(flow.redirect_uri);
    const search = new URLSearchParams(params);
    if (flow.client_state !== undefined) {
        search.set("state", flow.client_state);
    }
    if (flow.response_mode === "fragment") {
        url.hash = search.toString();
    } else {
        for (const [key, value] of search) {
            url.searchParams.set(key, value);
        }
    }
    return url.toString();
}

export function authRoutes(deps: AppDeps): Hono {
    const { config } = deps;
    const secureCookie = new URL(config.appBaseUrl).protocol === "https:";
    const app = new Hono();

    app.get("/google/login", async (c) => {
        const parsed = loginQuerySchema.safeParse(c.req.query());
        if (!parsed.success) {
            return c.json(
                {
                    error: "invalid_request",
                    error_description: "redirect_uri is missing or invalid"
                },
                400
            );
        }
        const query = parsed.data;
        // オープンリダイレクト防止のため、許可リストと完全一致したURIにのみ戻す
        if (!config.allowedRedirectUris.includes(query.redirect_uri)) {
            return c.json(
                {
                    error: "invalid_request",
                    error_description: "redirect_uri is not allowed"
                },
                400
            );
        }

        const state = randomToken();
        const nonce = randomToken();
        const { url, codeVerifier } = await createAuthorizationUrl(
            deps.googleClient,
            { state, nonce, hostedDomain: config.allowedDomain }
        );
        const sealed = await sealFlowState(
            {
                state,
                nonce,
                code_verifier: codeVerifier,
                redirect_uri: query.redirect_uri,
                client_state: query.state,
                response_mode: query.response_mode
            },
            config.sessionSecret
        );
        // Googleからのトップレベル遷移で送られるよう SameSite=Lax にする
        setCookie(c, FLOW_COOKIE, sealed, {
            path: COOKIE_PATH,
            httpOnly: true,
            secure: secureCookie,
            sameSite: "Lax",
            maxAge: FLOW_STATE_TTL_SECONDS
        });
        return c.redirect(url, 302);
    });

    app.get("/google/callback", async (c) => {
        const sealed = getCookie(c, FLOW_COOKIE);
        deleteCookie(c, FLOW_COOKIE, {
            path: COOKIE_PATH,
            secure: secureCookie
        });
        const flow = sealed
            ? await openFlowState(sealed, config.sessionSecret)
            : null;
        const query = callbackQuerySchema.safeParse(c.req.query());

        // フロー状態を検証できない場合は戻り先が信頼できないので、リダイレクトしない
        if (!flow || !query.success || query.data.state !== flow.state) {
            return c.json(
                {
                    error: "invalid_request",
                    error_description:
                        "Login session is missing, expired, or the state does not match"
                },
                400
            );
        }
        if (query.data.error || !query.data.code) {
            return c.redirect(
                buildClientRedirect(flow, {
                    error: "access_denied",
                    error_description: "Google authorization was not completed"
                }),
                302
            );
        }

        try {
            const idToken = await exchangeCodeForIdToken(
                deps.googleClient,
                query.data.code,
                flow.code_verifier
            );
            const googleUser = await verifyGoogleIdToken(
                deps.googleClient,
                idToken,
                {
                    clientId: config.google.clientId,
                    allowedDomain: config.allowedDomain,
                    nonce: flow.nonce
                }
            );
            const token = await issueToken(
                deps.keyStore,
                {
                    ...googleUser,
                    student_id: extractStudentId(googleUser.email)
                },
                {
                    issuer: config.tokenIssuer,
                    audience: config.tokenAudience
                }
            );
            return c.redirect(buildClientRedirect(flow, { token }), 302);
        } catch (err) {
            if (err instanceof GoogleAuthError) {
                return c.redirect(
                    buildClientRedirect(flow, {
                        error: "access_denied",
                        error_description: err.code
                    }),
                    302
                );
            }
            throw err;
        }
    });

    return app;
}
