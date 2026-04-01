# Transport 実装者向けセキュリティガイドライン

## 概要

Sentinel SDK は zero-dep 設計のため、gRPC/HTTP 等のトランスポート実装はユーザーが注入する。
本ドキュメントは `RemoteTransport` インターフェースを実装する際のセキュリティ要件を定義する。

## 必須要件

### 1. TLS 暗号化（必須）

本番環境では **TLS 1.2 以上** を必須とする。平文通信は禁止。

```typescript
// gRPC の場合
import * as grpc from "@grpc/grpc-js";
import { readFileSync } from "node:fs";

const credentials = grpc.credentials.createSsl(
    readFileSync("/path/to/ca.pem"),       // CA 証明書
    readFileSync("/path/to/client-key.pem"), // クライアント秘密鍵（mTLS）
    readFileSync("/path/to/client-cert.pem"), // クライアント証明書（mTLS）
);

const client = new SentinelServiceClient(addr, credentials);
```

### 2. mTLS（推奨）

マルチテナント環境やゼロトラスト環境では **mutual TLS** を推奨。
クライアント証明書でSDKインスタンスを認証する。

SDK の `TransportConfig.tls` フィールドに証明書パスを設定:

```typescript
Sentinel.initialize(config, {
    transport: {
        mode: "remote",
        transport: myGrpcTransport,
        tls: {
            caCertPath: "/etc/sentinel/ca.pem",
            clientCertPath: "/etc/sentinel/client.pem",
            clientKeyPath: "/etc/sentinel/client-key.pem",
        },
    },
});
```

### 3. タイムアウト設定

`timeoutMs` のデフォルトは 30,000ms (30秒)。
本番では以下を推奨:

| 環境 | 推奨値 | 理由 |
|------|--------|------|
| 同一リージョン | 5,000ms | ネットワーク遅延 < 10ms |
| クロスリージョン | 15,000ms | 遅延 50-200ms |
| 開発/テスト | 30,000ms | デフォルト |

### 4. 送信データの機密性

SDK は `masking.enabled: true` の場合、Transport に渡す前に PII をマスクする。
ただし以下のフィールドはマスク対象外:

- `traceId`, `spanId` (トレーシング用、preserveFields デフォルト)
- `type`, `level`, `boundary`, `serviceId` (メタデータ)

**注意**: `preserveFields` に機密フィールドを追加しないこと。
SDK は初期化時にセンシティブなフィールド名（password, token, secret 等）を検出して警告する。

### 5. 再送・リトライ

SDK はトランスポートレベルのリトライを行わない。
リトライが必要な場合はトランスポート実装側で対応:

```typescript
const transport: RemoteTransport = {
    async send(log) {
        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                return await client.ingest(log);
            } catch (err) {
                if (attempt === 2) throw err;
                await sleep(1000 * (attempt + 1)); // exponential backoff
            }
        }
        throw new Error("unreachable");
    },
};
```

### 6. ヘルスチェック

`healthCheck()` メソッドの実装を推奨。
サーバ接続前にヘルスチェックで確認:

```typescript
const transport = createGrpcTransport(addr);
const healthy = await transport.healthCheck?.();
if (!healthy) throw new Error("Server is not serving");
```

## セキュリティチェックリスト

- [ ] TLS 1.2+ を使用している
- [ ] 証明書の有効期限を監視している
- [ ] `preserveFields` にパスワード/トークンを含めていない
- [ ] タイムアウトを環境に応じて設定している
- [ ] ヘルスチェックを実装している
- [ ] エラーメッセージにサーバ内部情報を含めていない
