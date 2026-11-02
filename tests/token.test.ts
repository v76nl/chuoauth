import { createPrivateKey } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
    createKeyStore,
    getJwks,
    issueToken,
    TOKEN_TTL_SECONDS,
    type KeyStore
} from "../src/services/token.js";
import type { ChuoauthUser } from "../src/types/index.js";
import { generateTestKeys } from "./helpers.js";

const ISSUER = "https://auth.example.com";
const user: ChuoauthUser = {
    sub: "1234567890",
    email: "a0000000@g.chuo-u.ac.jp",
    domain: "g.chuo-u.ac.jp",
    student_id: "a0000000"
};

let keys: { privateKeyPem: string; publicKeyPem: string };
let store: KeyStore;

beforeAll(async () => {
    keys = await generateTestKeys();
    store = await createKeyStore({ keyId: "test-key", ...keys });
});

describe("createKeyStore", () => {
    it("公開鍵を省略すると秘密鍵から導出する", async () => {
        const derived = await createKeyStore({
            keyId: "test-key",
            privateKeyPem: keys.privateKeyPem
        });
        expect(derived.publicJwk).toEqual(store.publicJwk);
    });

    it("PKCS#1 形式の秘密鍵も受け付ける", async () => {
        const pkcs1 = createPrivateKey(keys.privateKeyPem)
            .export({ type: "pkcs1", format: "pem" })
            .toString();
        const fromPkcs1 = await createKeyStore({
            keyId: "test-key",
            privateKeyPem: pkcs1
        });
        expect(fromPkcs1.publicJwk).toEqual(store.publicJwk);
    });

    it("鍵ペアが一致しなければ失敗する", async () => {
        const other = await generateTestKeys();
        await expect(
            createKeyStore({
                keyId: "test-key",
                privateKeyPem: keys.privateKeyPem,
                publicKeyPem: other.publicKeyPem
            })
        ).rejects.toThrow("does not match");
    });
});

describe("getJwks", () => {
    it("公開鍵のみを JWKS 形式で返す", () => {
        const jwks = getJwks(store);
        expect(jwks.keys).toHaveLength(1);
        const [key] = jwks.keys;
        expect(key).toMatchObject({
            kty: "RSA",
            use: "sig",
            alg: "RS256",
            kid: "test-key",
            e: "AQAB"
        });
        expect(key).not.toHaveProperty("d");
    });
});

describe("issueToken", () => {
    it("JWKS で検証できる RS256 トークンを発行する", async () => {
        const token = await issueToken(store, user, { issuer: ISSUER });
        expect(decodeProtectedHeader(token)).toEqual({
            alg: "RS256",
            typ: "JWT",
            kid: "test-key"
        });

        const { payload } = await jwtVerify(
            token,
            createLocalJWKSet(getJwks(store)),
            { issuer: ISSUER, algorithms: ["RS256"] }
        );
        expect(payload).toMatchObject({
            iss: ISSUER,
            sub: user.sub,
            email: user.email,
            domain: user.domain,
            student_id: user.student_id
        });
        expect(payload.aud).toBeUndefined();
        expect(payload.exp! - payload.iat!).toBe(TOKEN_TTL_SECONDS);
    });

    it("student_id が null でもクレームとして含める", async () => {
        const token = await issueToken(
            store,
            { ...user, student_id: null },
            { issuer: ISSUER }
        );
        const { payload } = await jwtVerify(
            token,
            createLocalJWKSet(getJwks(store))
        );
        expect(payload).toHaveProperty("student_id", null);
    });

    it("audience を設定できる", async () => {
        const token = await issueToken(store, user, {
            issuer: ISSUER,
            audience: "chuoauth-discord"
        });
        const { payload } = await jwtVerify(
            token,
            createLocalJWKSet(getJwks(store)),
            { audience: "chuoauth-discord" }
        );
        expect(payload.aud).toBe("chuoauth-discord");
    });

    it("期限切れトークンは検証に失敗する", async () => {
        const token = await issueToken(store, user, {
            issuer: ISSUER,
            ttlSeconds: -1
        });
        await expect(
            jwtVerify(token, createLocalJWKSet(getJwks(store)))
        ).rejects.toThrow();
    });
});
