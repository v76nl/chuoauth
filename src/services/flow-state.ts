import { createHash, randomBytes } from "node:crypto";
import { EncryptJWT, jwtDecrypt } from "jose";
import { z } from "zod";

// 認可コードフロー中にブラウザへ預ける状態。暗号化してクッキーに保存する
const flowStateSchema = z.object({
    state: z.string(),
    nonce: z.string(),
    code_verifier: z.string(),
    redirect_uri: z.url(),
    client_state: z.string().optional(),
    response_mode: z.enum(["query", "fragment"])
});

export type FlowState = z.infer<typeof flowStateSchema>;

export const FLOW_STATE_TTL_SECONDS = 600;

export function randomToken(): string {
    return randomBytes(32).toString("base64url");
}

function deriveKey(secret: string): Uint8Array {
    return createHash("sha256").update(secret).digest();
}

export async function sealFlowState(
    flow: FlowState,
    secret: string
): Promise<string> {
    return new EncryptJWT(flow)
        .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
        .setIssuedAt()
        .setExpirationTime(`${FLOW_STATE_TTL_SECONDS}s`)
        .encrypt(deriveKey(secret));
}

/**
 * 改ざん・期限切れ・形式不正の場合は null を返す
 */
export async function openFlowState(
    sealed: string,
    secret: string
): Promise<FlowState | null> {
    try {
        const { payload } = await jwtDecrypt(sealed, deriveKey(secret));
        const result = flowStateSchema.safeParse(payload);
        return result.success ? result.data : null;
    } catch {
        return null;
    }
}
