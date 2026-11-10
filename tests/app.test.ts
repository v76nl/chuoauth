import type { OAuth2Client, TokenPayload } from "google-auth-library";
import type { Hono } from "hono";
import { createLocalJWKSet, jwtVerify, type JWK } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig, type Config } from "../src/config.js";
import { openFlowState } from "../src/services/flow-state.js";
import { createGoogleClient } from "../src/services/google.js";
import { createKeyStore } from "../src/services/token.js";
import { generateTestKeys } from "./helpers.js";

const CLIENT_REDIRECT = "http://localhost:5173/callback";

let config: Config;
let app: Hono;
let googleClient: OAuth2Client;

function googlePayload(nonce?: string): TokenPayload {
    const now = Math.floor(Date.now() / 1000);
    return {
        iss: "https://accounts.google.com",
        aud: config.google.clientId,
        sub: "1234567890",
        iat: now,
        exp: now + 3600,
        email: "a0000000@g.chuo-u.ac.jp",
        email_verified: true,
        hd: "g.chuo-u.ac.jp",
        nonce
    };
}

function stubVerify(payload: TokenPayload) {
    vi.spyOn(googleClient, "verifyIdToken").mockImplementation((async () => ({
        getPayload: () => payload
    })) as never);
}

async function jwks() {
    const res = await app.request("/.well-known/jwks.json");
    return createLocalJWKSet((await res.json()) as { keys: JWK[] });
}

async function startLogin(query: string) {
    const res = await app.request(`/auth/google/login?${query}`);
    const cookie = res.headers.get("set-cookie") ?? "";
    const sealed = /chuoauth_flow=([^;]+)/.exec(cookie)?.[1] ?? "";
    return { res, cookie: `chuoauth_flow=${sealed}`, sealed };
}

beforeAll(async () => {
    const keys = await generateTestKeys();
    config = loadConfig({
        NODE_ENV: "test",
        APP_BASE_URL: "http://localhost:3000",
        TOKEN_ISSUER: "https://auth.example.com",
        GOOGLE_CLIENT_ID: "client-id.apps.googleusercontent.com",
        GOOGLE_CLIENT_SECRET: "secret",
        GOOGLE_REDIRECT_URI: "http://localhost:3000/auth/google/callback",
        JWT_KEY_ID: "test-key",
        JWT_PRIVATE_KEY: keys.privateKeyPem.replace(/\n/g, "\\n"),
        SESSION_SECRET: "x".repeat(32),
        ALLOWED_REDIRECT_URIS: `${CLIENT_REDIRECT}, https://app.example.com/cb`
    });
    googleClient = createGoogleClient(config.google);
    app = createApp({
        config,
        keyStore: await createKeyStore(config.jwt),
        googleClient
    });
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe("GET /health", () => {
    it("ok を返す", async () => {
        const res = await app.request("/health");
        expect(await res.json()).toEqual({ status: "ok" });
    });
});

describe("GET /.well-known/jwks.json", () => {
    it("CORS 許可付きで公開鍵を返す", async () => {
        const res = await app.request("/.well-known/jwks.json", {
            headers: { Origin: "https://anywhere.example.com" }
        });
        expect(res.headers.get("access-control-allow-origin")).toBe("*");
        const body = (await res.json()) as { keys: JWK[] };
        expect(body.keys[0]?.kid).toBe("test-key");
    });
});

describe("GET /auth/google/login", () => {
    it("許可されていない redirect_uri は拒否", async () => {
        const res = await app.request(
            "/auth/google/login?redirect_uri=https://evil.example.com/cb"
        );
        expect(res.status).toBe(400);
    });

    it("redirect_uri がなければ拒否", async () => {
        const res = await app.request("/auth/google/login");
        expect(res.status).toBe(400);
    });

    it("hd・PKCE・nonce 付きで Google にリダイレクトし、フロー状態を暗号化クッキーに保存する", async () => {
        const { res, cookie, sealed } = await startLogin(
            `redirect_uri=${encodeURIComponent(CLIENT_REDIRECT)}&state=client-state`
        );
        expect(res.status).toBe(302);
        const location = new URL(res.headers.get("location")!);
        expect(location.hostname).toBe("accounts.google.com");
        expect(location.searchParams.get("hd")).toBe("g.chuo-u.ac.jp");
        expect(location.searchParams.get("code_challenge_method")).toBe("S256");
        expect(location.searchParams.get("scope")).toBe("openid email");

        expect(cookie).toContain("chuoauth_flow=");
        expect(res.headers.get("set-cookie")).toMatch(/HttpOnly/i);
        const flow = await openFlowState(sealed, config.sessionSecret);
        expect(flow).toMatchObject({
            state: location.searchParams.get("state"),
            nonce: location.searchParams.get("nonce"),
            redirect_uri: CLIENT_REDIRECT,
            client_state: "client-state"
        });
        // クライアント側の state はGoogleに送らない
        expect(location.searchParams.get("state")).not.toBe("client-state");
    });
});

describe("GET /auth/google/callback", () => {
    it("クッキーがなければリダイレクトせず拒否", async () => {
        const res = await app.request("/auth/google/callback?code=c&state=s");
        expect(res.status).toBe(400);
    });

    it("state が一致しなければ拒否", async () => {
        const { cookie } = await startLogin(
            `redirect_uri=${encodeURIComponent(CLIENT_REDIRECT)}`
        );
        const res = await app.request(
            "/auth/google/callback?code=c&state=forged",
            { headers: { Cookie: cookie } }
        );
        expect(res.status).toBe(400);
    });

    it("成功時は redirect_uri にトークンと state を付けて戻す", async () => {
        const { cookie, sealed } = await startLogin(
            `redirect_uri=${encodeURIComponent(CLIENT_REDIRECT)}&state=client-state`
        );
        const flow = (await openFlowState(sealed, config.sessionSecret))!;
        const getToken = vi
            .spyOn(googleClient, "getToken")
            .mockImplementation((async () => ({
                tokens: { id_token: "google-id-token" }
            })) as never);
        stubVerify(googlePayload(flow.nonce));

        const res = await app.request(
            `/auth/google/callback?code=auth-code&state=${flow.state}`,
            { headers: { Cookie: cookie } }
        );
        expect(res.status).toBe(302);
        expect(getToken).toHaveBeenCalledWith({
            code: "auth-code",
            codeVerifier: flow.code_verifier
        });

        const location = new URL(res.headers.get("location")!);
        expect(`${location.origin}${location.pathname}`).toBe(CLIENT_REDIRECT);
        expect(location.searchParams.get("state")).toBe("client-state");
        const { payload } = await jwtVerify(
            location.searchParams.get("token")!,
            await jwks(),
            { issuer: "https://auth.example.com" }
        );
        expect(payload).toMatchObject({
            email: "a0000000@g.chuo-u.ac.jp"
        });
        expect(payload).not.toHaveProperty("student_id");
    });

    it("fragment モードではトークンをフラグメントに載せる", async () => {
        const { cookie, sealed } = await startLogin(
            `redirect_uri=${encodeURIComponent(CLIENT_REDIRECT)}&response_mode=fragment`
        );
        const flow = (await openFlowState(sealed, config.sessionSecret))!;
        vi.spyOn(googleClient, "getToken").mockImplementation((async () => ({
            tokens: { id_token: "google-id-token" }
        })) as never);
        stubVerify(googlePayload(flow.nonce));

        const res = await app.request(
            `/auth/google/callback?code=auth-code&state=${flow.state}`,
            { headers: { Cookie: cookie } }
        );
        const location = new URL(res.headers.get("location")!);
        expect(location.search).toBe("");
        expect(
            new URLSearchParams(location.hash.slice(1)).get("token")
        ).toBeTruthy();
    });

    it("ドメイン違いならエラー付きで redirect_uri に戻す", async () => {
        const { cookie, sealed } = await startLogin(
            `redirect_uri=${encodeURIComponent(CLIENT_REDIRECT)}`
        );
        const flow = (await openFlowState(sealed, config.sessionSecret))!;
        vi.spyOn(googleClient, "getToken").mockImplementation((async () => ({
            tokens: { id_token: "google-id-token" }
        })) as never);
        stubVerify({
            ...googlePayload(flow.nonce),
            hd: undefined,
            email: "someone@gmail.com"
        });

        const res = await app.request(
            `/auth/google/callback?code=auth-code&state=${flow.state}`,
            { headers: { Cookie: cookie } }
        );
        const location = new URL(res.headers.get("location")!);
        expect(location.searchParams.get("error")).toBe("access_denied");
        expect(location.searchParams.get("error_description")).toBe(
            "domain_not_allowed"
        );
        expect(location.searchParams.get("token")).toBeNull();
    });
});

describe("POST /api/verify", () => {
    it("id_token がなければ 400", async () => {
        const res = await app.request("/api/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}"
        });
        expect(res.status).toBe(400);
    });

    it("検証に成功するとトークンとユーザー情報を返す", async () => {
        stubVerify(googlePayload());
        const res = await app.request("/api/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id_token: "google-id-token" })
        });
        expect(res.status).toBe(200);
        const body = (await res.json()) as {
            token: string;
            user: Record<string, unknown>;
        };
        expect(body.user).toEqual({
            email: "a0000000@g.chuo-u.ac.jp",
            domain: "g.chuo-u.ac.jp"
        });
        await expect(jwtVerify(body.token, await jwks())).resolves.toBeTruthy();
    });

    it("検証に失敗すると 401", async () => {
        stubVerify({ ...googlePayload(), hd: "example.com" });
        const res = await app.request("/api/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id_token: "google-id-token" })
        });
        expect(res.status).toBe(401);
    });

    it("許可オリジンにのみ CORS を返す", async () => {
        const allowed = await app.request("/api/verify", {
            method: "OPTIONS",
            headers: {
                Origin: "http://localhost:5173",
                "Access-Control-Request-Method": "POST"
            }
        });
        expect(allowed.headers.get("access-control-allow-origin")).toBe(
            "http://localhost:5173"
        );
        const denied = await app.request("/api/verify", {
            method: "OPTIONS",
            headers: {
                Origin: "https://evil.example.com",
                "Access-Control-Request-Method": "POST"
            }
        });
        expect(denied.headers.get("access-control-allow-origin")).toBeNull();
    });
});
