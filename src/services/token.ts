import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { exportJWK, SignJWT, type JWK } from "jose";
import type { ChuoauthUser } from "../types/index.js";

const ALGORITHM = "RS256";
export const TOKEN_TTL_SECONDS = 600;

export type KeyStore = {
    kid: string;
    privateKey: KeyObject;
    publicJwk: JWK;
};

export type IssueOptions = {
    issuer: string;
    audience?: string;
    ttlSeconds?: number;
};

/**
 * PEM形式の鍵からキーストアを作る。秘密鍵は PKCS#1 / PKCS#8 のどちらも受け付ける。
 * 公開鍵が省略された場合は秘密鍵から導出する
 */
export async function createKeyStore(options: {
    keyId: string;
    privateKeyPem: string;
    publicKeyPem?: string;
}): Promise<KeyStore> {
    const privateKey = createPrivateKey(options.privateKeyPem);
    if (privateKey.asymmetricKeyType !== "rsa") {
        throw new Error("JWT_PRIVATE_KEY must be an RSA private key");
    }
    const modulusLength = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (modulusLength < 2048) {
        throw new Error("JWT_PRIVATE_KEY must be at least 2048 bits");
    }

    const derivedPublicKey = createPublicKey(privateKey);
    if (options.publicKeyPem) {
        const given = createPublicKey(options.publicKeyPem);
        if (!given.equals(derivedPublicKey)) {
            throw new Error("JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY");
        }
    }

    const jwk = await exportJWK(derivedPublicKey);
    return {
        kid: options.keyId,
        privateKey,
        publicJwk: {
            kty: jwk.kty,
            use: "sig",
            alg: ALGORITHM,
            kid: options.keyId,
            n: jwk.n,
            e: jwk.e
        }
    };
}

export async function issueToken(
    store: KeyStore,
    user: ChuoauthUser,
    options: IssueOptions
): Promise<string> {
    const jwt = new SignJWT({
        email: user.email,
        domain: user.domain,
        student_id: user.student_id
    })
        .setProtectedHeader({ alg: ALGORITHM, typ: "JWT", kid: store.kid })
        .setIssuer(options.issuer)
        .setSubject(user.sub)
        .setIssuedAt()
        .setExpirationTime(`${options.ttlSeconds ?? TOKEN_TTL_SECONDS}s`);
    if (options.audience) {
        jwt.setAudience(options.audience);
    }
    return jwt.sign(store.privateKey);
}

export function getJwks(store: KeyStore): { keys: JWK[] } {
    return { keys: [store.publicJwk] };
}
