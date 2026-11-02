import { z } from "zod";

// Google IDトークンの検証を通過したユーザー
export type VerifiedGoogleUser = {
    sub: string;
    email: string;
    domain: string;
};

export type ChuoauthUser = VerifiedGoogleUser & {
    student_id: string | null;
};

// chuoauthが発行するJWTのペイロード
export type ChuoauthTokenPayload = {
    iss: string;
    sub: string;
    aud?: string;
    exp: number;
    iat: number;
    email: string;
    domain: string;
    student_id: string | null;
};

export const loginQuerySchema = z.object({
    redirect_uri: z.url(),
    state: z.string().min(1).max(512).optional(),
    response_mode: z.enum(["query", "fragment"]).default("query")
});

export type LoginQuery = z.infer<typeof loginQuerySchema>;

export const callbackQuerySchema = z.object({
    code: z.string().min(1).optional(),
    state: z.string().min(1).optional(),
    error: z.string().min(1).optional()
});

export const verifyRequestSchema = z.object({
    id_token: z.string().min(1)
});

export type VerifyResponse = {
    token: string;
    user: {
        email: string;
        student_id: string | null;
        domain: string;
    };
};

export type ErrorResponse = {
    error: string;
    error_description?: string;
};
