import { z } from "zod";

// .env では改行を "\n" とエスケープして1行で書くため、実際の改行に戻す
const pem = z
    .string()
    .min(1)
    .transform((value) => value.replace(/\\n/g, "\n"));

const urlList = z
    .string()
    .default("")
    .transform((value) =>
        value
            .split(",")
            .map((item) => item.trim())
            .filter((item) => item.length > 0)
    )
    .pipe(z.array(z.url()));

const envSchema = z.object({
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    NODE_ENV: z
        .enum(["development", "production", "test"])
        .default("development"),
    APP_BASE_URL: z.url(),
    TOKEN_ISSUER: z.url().optional(),
    TOKEN_AUDIENCE: z.string().min(1).optional(),
    ALLOWED_DOMAIN: z.string().min(1).default("g.chuo-u.ac.jp"),
    GOOGLE_CLIENT_ID: z.string().min(1),
    GOOGLE_CLIENT_SECRET: z.string().min(1),
    GOOGLE_REDIRECT_URI: z.url(),
    JWT_KEY_ID: z.string().min(1),
    JWT_PRIVATE_KEY: pem,
    JWT_PUBLIC_KEY: pem.optional(),
    SESSION_SECRET: z.string().min(32),
    ALLOWED_REDIRECT_URIS: urlList
});

export type Config = {
    port: number;
    nodeEnv: "development" | "production" | "test";
    appBaseUrl: string;
    tokenIssuer: string;
    tokenAudience?: string;
    allowedDomain: string;
    google: {
        clientId: string;
        clientSecret: string;
        redirectUri: string;
    };
    jwt: {
        keyId: string;
        privateKeyPem: string;
        publicKeyPem?: string;
    };
    sessionSecret: string;
    allowedRedirectUris: string[];
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
    // 空文字の環境変数は未設定として扱い、default / optional を効かせる
    const normalized = Object.fromEntries(
        Object.entries(env).filter(([, value]) => value !== "")
    );
    const result = envSchema.safeParse(normalized);
    if (!result.success) {
        throw new Error(
            `Invalid environment variables:\n${z.prettifyError(result.error)}`
        );
    }
    const e = result.data;
    return {
        port: e.PORT,
        nodeEnv: e.NODE_ENV,
        appBaseUrl: e.APP_BASE_URL,
        tokenIssuer: e.TOKEN_ISSUER ?? e.APP_BASE_URL,
        tokenAudience: e.TOKEN_AUDIENCE,
        allowedDomain: e.ALLOWED_DOMAIN,
        google: {
            clientId: e.GOOGLE_CLIENT_ID,
            clientSecret: e.GOOGLE_CLIENT_SECRET,
            redirectUri: e.GOOGLE_REDIRECT_URI
        },
        jwt: {
            keyId: e.JWT_KEY_ID,
            privateKeyPem: e.JWT_PRIVATE_KEY,
            publicKeyPem: e.JWT_PUBLIC_KEY
        },
        sessionSecret: e.SESSION_SECRET,
        allowedRedirectUris: e.ALLOWED_REDIRECT_URIS
    };
}
