import type { LoginTicket, TokenPayload } from "google-auth-library";
import { describe, expect, it, vi } from "vitest";
import {
    buildEmailPattern,
    GoogleAuthError,
    validateGoogleClaims,
    verifyGoogleIdToken,
    type GoogleVerifyOptions
} from "../src/services/google.js";

const NOW = Date.UTC(2026, 10, 1, 0, 0, 0);
const options: GoogleVerifyOptions = {
    clientId: "client-id.apps.googleusercontent.com",
    allowedDomain: "g.chuo-u.ac.jp",
    now: NOW
};

function payload(overrides: Partial<TokenPayload> = {}): TokenPayload {
    return {
        iss: "https://accounts.google.com",
        aud: options.clientId,
        sub: "1234567890",
        iat: NOW / 1000 - 60,
        exp: NOW / 1000 + 3600,
        email: "a0000000@g.chuo-u.ac.jp",
        email_verified: true,
        hd: "g.chuo-u.ac.jp",
        ...overrides
    };
}

function expectCode(fn: () => unknown, code: GoogleAuthError["code"]) {
    try {
        fn();
    } catch (err) {
        expect(err).toBeInstanceOf(GoogleAuthError);
        expect((err as GoogleAuthError).code).toBe(code);
        return;
    }
    throw new Error(`expected GoogleAuthError(${code})`);
}

describe("validateGoogleClaims", () => {
    it("全条件を満たすと利用者情報を返す", () => {
        expect(validateGoogleClaims(payload(), options)).toEqual({
            sub: "1234567890",
            email: "a0000000@g.chuo-u.ac.jp",
            domain: "g.chuo-u.ac.jp"
        });
    });

    it("スキームなしの iss も受け付ける", () => {
        expect(() =>
            validateGoogleClaims(
                payload({ iss: "accounts.google.com" }),
                options
            )
        ).not.toThrow();
    });

    it("ペイロードがなければ拒否", () => {
        expectCode(
            () => validateGoogleClaims(undefined, options),
            "invalid_token"
        );
    });

    it("iss が異なれば拒否", () => {
        expectCode(
            () =>
                validateGoogleClaims(
                    payload({ iss: "https://evil.example.com" }),
                    options
                ),
            "invalid_issuer"
        );
    });

    it("aud が異なれば拒否", () => {
        expectCode(
            () => validateGoogleClaims(payload({ aud: "other" }), options),
            "invalid_audience"
        );
    });

    it("期限切れなら拒否", () => {
        expectCode(
            () => validateGoogleClaims(payload({ exp: NOW / 1000 }), options),
            "token_expired"
        );
    });

    it("email_verified が true でなければ拒否", () => {
        expectCode(
            () =>
                validateGoogleClaims(
                    payload({ email_verified: false }),
                    options
                ),
            "email_not_verified"
        );
        expectCode(
            () =>
                validateGoogleClaims(
                    payload({ email_verified: undefined }),
                    options
                ),
            "email_not_verified"
        );
    });

    it("hd が欠落・不一致なら拒否 (個人Gmailや他大学)", () => {
        expectCode(
            () => validateGoogleClaims(payload({ hd: undefined }), options),
            "domain_not_allowed"
        );
        expectCode(
            () =>
                validateGoogleClaims(payload({ hd: "chuo-u.ac.jp" }), options),
            "domain_not_allowed"
        );
    });

    it("hd が一致してもメールのドメインが異なれば拒否", () => {
        expectCode(
            () =>
                validateGoogleClaims(
                    payload({ email: "a0000000@gmail.com" }),
                    options
                ),
            "invalid_email"
        );
        expectCode(
            () =>
                validateGoogleClaims(
                    payload({ email: "a0000000@g.chuo-u.ac.jp.evil.com" }),
                    options
                ),
            "invalid_email"
        );
    });

    it("nonce が指定されていれば一致を要求する", () => {
        const withNonce = { ...options, nonce: "expected" };
        expect(() =>
            validateGoogleClaims(payload({ nonce: "expected" }), withNonce)
        ).not.toThrow();
        expectCode(
            () => validateGoogleClaims(payload({ nonce: "other" }), withNonce),
            "nonce_mismatch"
        );
        expectCode(
            () => validateGoogleClaims(payload(), withNonce),
            "nonce_mismatch"
        );
    });
});

describe("buildEmailPattern", () => {
    it("ドメインの . をエスケープする", () => {
        const pattern = buildEmailPattern("g.chuo-u.ac.jp");
        expect(pattern.test("a0000000@g.chuo-u.ac.jp")).toBe(true);
        expect(pattern.test("a0000000@gxchuo-u.ac.jp")).toBe(false);
    });
});

describe("verifyGoogleIdToken", () => {
    it("署名検証後にクレームを検証する", async () => {
        const verifyIdToken = vi.fn().mockResolvedValue({
            getPayload: () => payload({ exp: Date.now() / 1000 + 3600 })
        } as unknown as LoginTicket);
        const user = await verifyGoogleIdToken({ verifyIdToken }, "id-token", {
            clientId: options.clientId,
            allowedDomain: options.allowedDomain
        });
        expect(user.email).toBe("a0000000@g.chuo-u.ac.jp");
        expect(verifyIdToken).toHaveBeenCalledWith({
            idToken: "id-token",
            audience: options.clientId
        });
    });

    it("署名検証に失敗すれば invalid_token", async () => {
        const verifyIdToken = vi.fn().mockRejectedValue(new Error("bad sig"));
        await expect(
            verifyGoogleIdToken({ verifyIdToken }, "id-token", options)
        ).rejects.toMatchObject({ code: "invalid_token" });
    });

    it("署名が正しくてもドメイン違いなら拒否", async () => {
        const verifyIdToken = vi.fn().mockResolvedValue({
            getPayload: () =>
                payload({
                    hd: undefined,
                    email: "someone@gmail.com",
                    exp: Date.now() / 1000 + 3600
                })
        } as unknown as LoginTicket);
        await expect(
            verifyGoogleIdToken({ verifyIdToken }, "id-token", {
                clientId: options.clientId,
                allowedDomain: options.allowedDomain
            })
        ).rejects.toMatchObject({ code: "domain_not_allowed" });
    });
});
