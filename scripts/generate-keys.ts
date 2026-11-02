// 開発用のRSA 2048bit鍵ペアとセッション秘密鍵を生成し、.env に貼り付けられる形式で出力する
import { randomBytes } from "node:crypto";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";

const { privateKey, publicKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    extractable: true
});

const toEnvValue = (pem: string) => pem.trim().replace(/\n/g, "\\n");
const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");

console.log(`JWT_KEY_ID=chuoauth-${date}`);
console.log(`JWT_PRIVATE_KEY="${toEnvValue(await exportPKCS8(privateKey))}"`);
console.log(`JWT_PUBLIC_KEY="${toEnvValue(await exportSPKI(publicKey))}"`);
console.log(`SESSION_SECRET=${randomBytes(32).toString("base64url")}`);
