# 機能の実装状況・TODO追跡

```yaml
analyzed_at: "2026-04-02"
based_on: "3227fe1"
status: current
```

## 宣言済み機能の実装状況

| 機能 | 宣言場所 | 実装状況 | カテゴリ |
|------|---------|---------|---------|
| デジタル署名 (`signature`) | log.ts:66 | 未実装。パススルーのみ | GAP |
| 署名鍵選択 (`signingKeyId`) | sentinel-config.ts:104 | 未実装 | GAP |
| Worker Thread通信 (`WorkerToMainMessage`) | — | ✅ 削除済み（DEAD-02） | DONE |
| `AI_ACTION_REQUIRED` イベント | event.ts:37-41 | ✅ event-detector.ts:103 で検知ルール実装済み（DEAD-04） | OK |
| `RemoteTransport.healthCheck()` | transport.ts:36 | optional インターフェース。SDK内で未呼出（利用者実装依存） | GAP |
| `RemoteTransport.close()` | transport.ts:41 | ✅ shutdown() で `transport?.close?.()` として呼出済み | OK |
| `SEMI_AUTO` 実行レベル | task-executor.ts:146-152 | ✅ TaskConfirmHandler で確認フロー実装済み（API-02） | OK |
| `guardrails.timeoutMs` | task.ts:49 | ✅ task-executor.ts:167-184 で Promise.race() により実装済み | OK |
| `guardrails.maxRetries` | task.ts:50 | ✅ task-executor.ts ハンドラ単位リトライで実装済み | OK |

## ソース内 TODO 一覧

| ファイル | 行 | 内容 | 優先度 |
|---------|---|------|--------|
| log.ts | 56 | ✅ `traceInfo` コメント明確化済み（分散トレーシング追加コンテキスト） | DONE |
| log.ts | 59 | ✅ `details?: Record<string, string>` に変更済み（Proto互換） | DONE |
| log.ts | 63 | ✅ `resourceIds` コメント明確化済み（影響対象リソースID） | DONE |
| log.ts | 72 | ✅ `actionType` を `TaskActionType` enum に変更済み | DONE |
| log.ts | 75 | ✅ `output?: AIAgentOutput` に型定義済み | DONE |
| error-utils.ts | 5 | `TODO 対象追加。PII検出正規表現（国際対応）` | NA (dead code) |
| error-payload-protocol.ts | 7 | `TODO di堅牢化（ホワイトリスト管理）` | NA (dead code) |

## 型エクスポートの必要性検証

| エクスポート | index.ts行 | 利用者に必要か | 備考 |
|-------------|-----------|--------------|------|
| `SystemEventName` | 415 | ✅ | IngestionResult.detection.eventName の型として必要 |
| `DetectionResult` | 415 | ✅ | DetectionRule 定義に必要 |
| `TaskSeverity` | 412 | ✅ | taskRules定義に必要 |
| `TaskExecutionLevel` | 413 | ✅ | taskRules定義に必要 |
| その他全て | — | ✅ | SDK利用に必要 |

## IngestionResult の情報不足

`IngestionResult` は `{ traceId, hashChainValid, tasksGenerated, masked, detection, transportError? }` を返す。

- ✅ `detection` フィールド追加済み（eventName + priority）（OBS-02）
- 処理済みログオブジェクト自体は返されない（`onLogProcessed` callback経由のみ — 設計上の意図）
- マスキングで何が除去されたかは返されない
