# chuoauth

中央大学の学生Googleアカウントで本人確認し、署名済みJWTを発行する独立認証プロバイダ

## 目次

1. [概要](#1-概要)
2. [仕組み](#2-仕組み)
3. [構造](#3-構造)
4. [実行方法](#4-実行方法)
5. [APIエンドポイント](#5-apiエンドポイント)
6. [クライアント側でのトークン検証](#6-クライアント側でのトークン検証)
7. [セキュリティ設計](#7-セキュリティ設計)

## 1. 概要

Google Workspaceの管理者権限を必要とせず、Google Cloud Consoleの標準OAuth 2.0クライアントのみで動作する。
`g.chuo-u.ac.jp` ドメインのアカウントであることをGoogleのIDトークンで検証し、chuoauth独自の短命JWT (有効期限10分) を発行する。
chuoauth-discord などの連携サービスは、`/.well-known/jwks.json` の公開鍵でJWTを検証するだけで学生認証を完結できる

```text
クライアント ──(1) /auth/google/login──> chuoauth ──(2) OAuth 2.0──> Google
                                           │  (3) hd・email等を検証
                                           │  (4) 独自JWTを署名
クライアント <──(redirect_uri?token=...)───┘
     │
     └──(5) /.well-known/jwks.json で公開鍵を取得し、署名を検証
```

## 2. 仕組み

- 言語: TypeScript (Node.js 20以上)
- HTTPフレームワーク: Hono + `@hono/node-server`
- JWT: `jose` (RS256)
- Google認証: `google-auth-library`
- バリデーション: `zod`
- テスト: Vitest
- パッケージマネージャー: pnpm

## 3. 構造

```text
chuoauth/
├── src/
│   ├── index.ts
│   ├── app.ts                 - Honoインスタンス、ミドルウェア、ルート登録
│   ├── config.ts              - 環境変数の読み込みとzodによる検証
│   ├── routes/
│   │   ├── auth.ts            - /auth/google/login, /auth/google/callback
│   │   ├── api.ts             - /api/verify
│   │   └── well-known.ts      - /.well-known/jwks.json
│   ├── services/
│   │   ├── google.ts          - 認可URL生成、コード交換、IDトークン検証
│   │   ├── token.ts           - JWT署名、キーストア、JWKS出力
│   │   ├── flow-state.ts      - ログイン中の状態を暗号化クッキーに封入
│   │   └── student-id.ts      - メールアドレスから学籍番号を抽出
│   └── types/
│       └── index.ts           - ペイロード型、リクエストスキーマ
├── scripts/
│   └── generate-keys.ts       - 開発用RSA鍵ペアとSESSION_SECRETの生成
├── tests/
│   ├── app.test.ts            - エンドポイントの結合テスト
│   ├── google.test.ts
│   ├── token.test.ts
│   ├── student-id.test.ts
│   └── helpers.ts             - テスト用鍵生成
├── .env.example
├── Dockerfile
├── package.json
├── pnpm-workspace.yaml        - pnpmのビルドスクリプト許可設定
├── tsconfig.json
└── tsconfig.build.json        - 本番ビルド (dist/ 出力) 用
```

## 4. 実行方法

### 準備

1. Google Cloud Consoleで「OAuth クライアント ID (ウェブアプリケーション)」を作成し、承認済みリダイレクトURIに `GOOGLE_REDIRECT_URI` と同じ値を登録する
2. `.env.example` を `.env` にコピーし、Googleのクライアント情報と `ALLOWED_REDIRECT_URIS` を設定する
3. `pnpm generate-keys` の出力 (`JWT_KEY_ID`、`JWT_PRIVATE_KEY`、`JWT_PUBLIC_KEY`、`SESSION_SECRET`) を `.env` に貼り付ける

### コマンド

| コマンド             | 実行内容                                  |
| -------------------- | ----------------------------------------- |
| `pnpm install`       | パッケージのインストール                  |
| `pnpm dev`           | 開発サーバーの起動 (ファイル変更で再起動) |
| `pnpm build`         | `dist/` へのビルド                        |
| `pnpm start`         | ビルド済みサーバーの起動                  |
| `pnpm test`          | テストの実行                              |
| `pnpm typecheck`     | 型チェック                                |
| `pnpm generate-keys` | 開発用の鍵とセッション秘密値の生成        |
| `pnpm format`        | Prettierによる整形                        |

### Docker

```bash
docker build -t chuoauth .
docker run --env-file .env -p 3000:3000 chuoauth
```

### 環境変数

| 変数                    | 必須 | 説明                                                         |
| ----------------------- | ---- | ------------------------------------------------------------ |
| `PORT`                  |      | 待受ポート (既定: 3000)                                      |
| `APP_BASE_URL`          | 必須 | 公開URL。`https:` の場合はクッキーに Secure 属性を付与       |
| `TOKEN_ISSUER`          |      | 発行JWTの `iss` (既定: `APP_BASE_URL`)                       |
| `TOKEN_AUDIENCE`        |      | 発行JWTの `aud`。未設定なら `aud` を含めない                 |
| `ALLOWED_DOMAIN`        |      | 許可するWorkspaceドメイン (既定: `g.chuo-u.ac.jp`)           |
| `GOOGLE_CLIENT_ID`      | 必須 |                                                              |
| `GOOGLE_CLIENT_SECRET`  | 必須 |                                                              |
| `GOOGLE_REDIRECT_URI`   | 必須 | `/auth/google/callback` の完全なURL                          |
| `JWT_KEY_ID`            | 必須 | JWTヘッダーとJWKSの `kid`                                    |
| `JWT_PRIVATE_KEY`       | 必須 | RSA秘密鍵 (PEM、改行は `\n`)。PKCS#8 / PKCS#1 どちらも可     |
| `JWT_PUBLIC_KEY`        |      | 省略時は秘密鍵から導出。指定時は秘密鍵との一致を起動時に検証 |
| `SESSION_SECRET`        | 必須 | ログイン状態クッキーの暗号化キー (32文字以上)                |
| `ALLOWED_REDIRECT_URIS` | 必須 | 戻り先として許可するURI (カンマ区切り、完全一致)             |

## 5. APIエンドポイント

| メソッド | パス                     | 説明                                                  |
| -------- | ------------------------ | ----------------------------------------------------- |
| GET      | `/auth/google/login`     | 認可コードフローを開始し、Googleへリダイレクト        |
| GET      | `/auth/google/callback`  | Googleからの戻り先。JWTを付けて `redirect_uri` へ戻す |
| POST     | `/api/verify`            | GISで取得したIDトークンを直接検証してJWTを返す        |
| GET      | `/.well-known/jwks.json` | 署名検証用の公開鍵 (JWKS)                             |
| GET      | `/health`                | `{"status":"ok"}`                                     |

### `GET /auth/google/login`

| クエリ          | 必須 | 説明                                                 |
| --------------- | ---- | ---------------------------------------------------- |
| `redirect_uri`  | 必須 | `ALLOWED_REDIRECT_URIS` のいずれかと完全一致すること |
| `state`         |      | クライアントのCSRF対策値。戻り先にそのまま付与される |
| `response_mode` |      | `query` (既定) または `fragment`                     |

成功時: `redirect_uri?token=<JWT>&state=<state>`
失敗時: `redirect_uri?error=access_denied&error_description=<理由>&state=<state>`
(`fragment` 指定時は `#` 以降に同じパラメータが付く)

`error_description` には `domain_not_allowed` (中大以外のアカウント)、`email_not_verified` などが入る。
ログインセッションの期限切れや state 不一致など、戻り先を信頼できない場合はリダイレクトせず 400 を返す

### `POST /api/verify`

```json
// リクエスト
{ "id_token": "eyJhbGciOiJSUzI1NiIs..." }

// レスポンス 200
{
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "user": {
        "email": "a0000000@g.chuo-u.ac.jp",
        "student_id": "a0000000",
        "domain": "g.chuo-u.ac.jp"
    }
}
```

検証失敗時は 401 `{"error":"invalid_token","error_description":"<理由>"}`。
CORSは `ALLOWED_REDIRECT_URIS` のオリジンのみ許可する。
GIS側のクライアントIDは `GOOGLE_CLIENT_ID` と同じものを使うこと

### 発行JWT

| クレーム     | 内容                                      |
| ------------ | ----------------------------------------- |
| `iss`        | `TOKEN_ISSUER`                            |
| `sub`        | Googleアカウントの固有ID                  |
| `aud`        | `TOKEN_AUDIENCE` (設定時のみ)             |
| `iat`, `exp` | 発行時刻と有効期限 (10分)                 |
| `email`      | メールアドレス                            |
| `domain`     | 所属ドメイン (`hd`)                       |
| `student_id` | 学籍番号。教職員など形式外の場合は `null` |

ヘッダーは `alg: RS256`、`typ: JWT`、`kid: JWT_KEY_ID`

## 6. クライアント側でのトークン検証

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

// JWKSはjose側でキャッシュされる
const jwks = createRemoteJWKSet(
    new URL("https://auth.example.com/.well-known/jwks.json")
);

const { payload } = await jwtVerify(token, jwks, {
    issuer: "https://auth.example.com",
    algorithms: ["RS256"]
    // audience: "chuoauth-discord" (TOKEN_AUDIENCE を設定した場合)
});
console.log(payload.email, payload.student_id);
```

## 7. セキュリティ設計

- Googleのトークンは `iss`、`aud`、`exp`、`email_verified`、`hd`、メールアドレス形式をすべて満たす場合のみ受理する。`hd` の付与はアカウント選択画面の絞り込みにすぎないため、必ずサーバー側で検証している
- `iss` はGoogleの仕様どおり `https://accounts.google.com` と `accounts.google.com` の両方を受理する
- 認可コードフローでは state (CSRF)、nonce (IDトークンの差し替え防止)、PKCE (認可コード横取り防止) を併用する。これらと戻り先は `SESSION_SECRET` で暗号化 (A256GCM) したHttpOnlyクッキーに保持し、サーバー側にセッションストアは持たない
- `redirect_uri` は許可リストとの完全一致のみ許可し、オープンリダイレクトを防ぐ
- アクセスログにはクエリ文字列 (認可コード等) を出力しない
- 学籍番号の抽出規則 (英字1文字 + 数字7桁) は `src/services/student-id.ts` の `STUDENT_ID_PATTERN` で調整できる
