# 未使用コード棚卸し

```yaml
analyzed_at: "2026-04-02"
based_on: "0ed9ab5"
status: current
```

## パイプラインから到達不能なモジュール

### ~~shared/functional/result.ts~~ — ✅ 削除済み

v1のWAL/persistence層の残骸。パイプライン未使用のため削除。テスト（result.test.ts）も削除。
`safe()` 関数はセキュリティテスト (new-findings-v2.test.ts) で使用されていたため、テストファイル内にインライン化。

### shared/errors/ [DEAD — ディレクトリ全体]

| ファイル | 内容 | 行数 |
|---------|------|------|
| `errors/index.ts` | **空ファイル** | 0 |
| `errors/application/auth-error.ts` | **空ファイル** | 0 |
| `errors/application/validation-error.ts` | `WalErrorKind` 型定義（ファイル名と不一致） | 6 |
| `errors/error-payload-protocol.ts` | `ErrorPayloadProtocol`, `ErrorMeta` インターフェース | ~30 |

`ErrorPayloadProtocol` は `error-utils.ts` の引数型として使われるが、`error-utils.ts` 自体がパイプラインから孤立。

### shared/utils/error-utils.ts [一部パイプライン接続済み]

`maskPiiContext` は `ConsoleAuditSink` (error-routing/sinks/) で使用済み。`serializeForAudit` 相当の構造化出力も同 Sink 内で実装。残りの `isPiiSafe`, `logFinancialError`, `classifyError`, `getErrorMessage` は直接未使用だが、将来の Sink 拡張で利用可能。

### shared/utils/seed-to-union-types.ts [DEAD]

`unionToArray`, `createIsUnionMember` ユーティリティ。インポートなし。

### shared/constants/ [DEAD — ディレクトリ全体]

| ファイル | 内容 |
|---------|------|
| `error-layer.ts` | `ERROR_LAYERS` 定数 |
| `http-status.ts` | `HTTP_STATUS` 定数 |
| `error-protocol-kind.ts` | `ERROR_KIND` 定数 |
| `kinds/application/*` | access, auth, limit-over, permission, security, validation 各error kind |
| `kinds/persistence/*` | cache, datastore, db, storage 各error kind |

これらは金融エラーハンドリング基盤として設計されたが、Sentinel v2パイプラインでは使用されていない。

### types/event.ts: WorkerToMainMessage [DEAD — 型定義のみ]

Worker Thread通信メッセージ型。Worker Thread実装は存在しない。

## Log型上の未使用フィールド

| フィールド | 定義 | パイプラインでの消費 | ステータス |
|-----------|------|-------------------|-----------|
| `signature` | log.ts:66 | omitされるのみ | DEAD — 署名機能未実装 |
| `traceInfo` | log.ts:56 | ✅ normalizeで保持済み (BUG-02対応) | OK |
| `agentBackLog` | log.ts:58 | ✅ normalizeで保持済み (BUG-01対応) | OK |

## 集計

| カテゴリ | ファイル数 | 推定行数 |
|---------|----------|---------|
| 完全DEAD（到達不能） | ~20ファイル | ~500行 |
| 部分DEAD（型定義のみ） | 1箇所 | ~10行 |
| ~~BUG伴うDEAD~~ | ~~2フィールド~~ | ✅ 修正済み |
