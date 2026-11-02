import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";

export async function generateTestKeys(): Promise<{
    privateKeyPem: string;
    publicKeyPem: string;
}> {
    const { privateKey, publicKey } = await generateKeyPair("RS256", {
        modulusLength: 2048,
        extractable: true
    });
    return {
        privateKeyPem: await exportPKCS8(privateKey),
        publicKeyPem: await exportSPKI(publicKey)
    };
}
