import {
    CodeChallengeMethod,
    OAuth2Client,
    type TokenPayload
} from "google-auth-library";
import type { VerifiedGoogleUser } from "../types/index.js";

// Googleは iss としてどちらの表記も発行しうると明記している
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

export type GoogleAuthErrorCode =
    | "invalid_token"
    | "invalid_issuer"
    | "invalid_audience"
    | "token_expired"
    | "email_not_verified"
    | "domain_not_allowed"
    | "invalid_email"
    | "nonce_mismatch"
    | "code_exchange_failed";

export class GoogleAuthError extends Error {
    constructor(
        readonly code: GoogleAuthErrorCode,
        message: string
    ) {
        super(message);
        this.name = "GoogleAuthError";
    }
}

export type GoogleVerifyOptions = {
    clientId: string;
    allowedDomain: string;
    // 認可コードフローで送ったnonce。GISから直接受け取る場合は省略
    nonce?: string;
    now?: number;
};

export function createGoogleClient(options: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
}): OAuth2Client {
    return new OAuth2Client({
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        redirectUri: options.redirectUri
    });
}

export function buildEmailPattern(domain: string): RegExp {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`^[a-zA-Z0-9._%+-]+@${escaped}$`);
}

/**
 * 署名検証済みのIDトークンペイロードに対し、仕様上の全条件を論理積で評価する
 */
export function validateGoogleClaims(
    payload: TokenPayload | undefined,
    options: GoogleVerifyOptions
): VerifiedGoogleUser {
    if (!payload) {
        throw new GoogleAuthError("invalid_token", "ID token has no payload");
    }
    if (!GOOGLE_ISSUERS.includes(payload.iss)) {
        throw new GoogleAuthError("invalid_issuer", "Unexpected issuer");
    }
    if (payload.aud !== options.clientId) {
        throw new GoogleAuthError("invalid_audience", "Unexpected audience");
    }
    const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) {
        throw new GoogleAuthError("token_expired", "ID token has expired");
    }
    if (payload.email_verified !== true) {
        throw new GoogleAuthError(
            "email_not_verified",
            "Email address is not verified"
        );
    }
    if (payload.hd !== options.allowedDomain) {
        throw new GoogleAuthError(
            "domain_not_allowed",
            `Only ${options.allowedDomain} accounts are allowed`
        );
    }
    const email = payload.email;
    if (!email || !buildEmailPattern(options.allowedDomain).test(email)) {
        throw new GoogleAuthError("invalid_email", "Email address is invalid");
    }
    if (options.nonce !== undefined && payload.nonce !== options.nonce) {
        throw new GoogleAuthError("nonce_mismatch", "Nonce mismatch");
    }
    return { sub: payload.sub, email, domain: payload.hd };
}

/**
 * Googleの公開鍵で署名を検証したうえで、クレームを検証する
 */
export async function verifyGoogleIdToken(
    client: Pick<OAuth2Client, "verifyIdToken">,
    idToken: string,
    options: GoogleVerifyOptions
): Promise<VerifiedGoogleUser> {
    let payload: TokenPayload | undefined;
    try {
        const ticket = await client.verifyIdToken({
            idToken,
            audience: options.clientId
        });
        payload = ticket.getPayload();
    } catch {
        throw new GoogleAuthError(
            "invalid_token",
            "ID token verification failed"
        );
    }
    return validateGoogleClaims(payload, options);
}

export async function createAuthorizationUrl(
    client: OAuth2Client,
    options: { state: string; nonce: string; hostedDomain: string }
): Promise<{ url: string; codeVerifier: string }> {
    const { codeVerifier, codeChallenge } =
        await client.generateCodeVerifierAsync();
    const url = client.generateAuthUrl({
        scope: ["openid", "email"],
        state: options.state,
        nonce: options.nonce,
        hd: options.hostedDomain,
        prompt: "select_account",
        code_challenge: codeChallenge,
        code_challenge_method: CodeChallengeMethod.S256
    });
    return { url, codeVerifier };
}

export async function exchangeCodeForIdToken(
    client: OAuth2Client,
    code: string,
    codeVerifier: string
): Promise<string> {
    let idToken: string | null | undefined;
    try {
        const { tokens } = await client.getToken({ code, codeVerifier });
        idToken = tokens.id_token;
    } catch {
        throw new GoogleAuthError(
            "code_exchange_failed",
            "Failed to exchange authorization code"
        );
    }
    if (!idToken) {
        throw new GoogleAuthError(
            "code_exchange_failed",
            "Token response did not include an ID token"
        );
    }
    return idToken;
}
