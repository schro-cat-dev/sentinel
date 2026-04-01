# 機能の実装状況・TODO追跡

```yaml
analyzed_at: "2026-04-01"
based_on: "b14d263"
status: current
```

## 宣言済み機能の実装状況

| 機能 | 宣言場所 | 実装状況 | カテゴリ |
|------|---------|---------|---------|
| デジタル署名 (`signature`) | log.ts:63 | 未実装。パススルーのみ | GAP |
| 署名鍵選択 (`signingKeyId`) | sentinel-config.ts:28 | 未実装 | GAP |
| Worker Thread通信 (`WorkerToMainMessage`) | event.ts:59-71 | 未実装。型定義のみ | DEAD |
| `AI_ACTION_REQUIRED` イベント | event.ts:37-41 | 型は存在するが検知ルールなし | GAP |
| `RemoteTransport.healthCheck()` | transport.ts:36 | 宣言のみ。SDK内で未呼出 | GAP |
| `RemoteTransport.close()` | transport.ts:40 | 宣言のみ。SDK内で未呼出 | GAP |
| `SEMI_AUTO` 実行レベル | task-executor.ts:70-71 | `AUTO` と同じ動作。区別なし | GAP |
| `guardrails.timeoutMs` | task.ts:49 | 必須フィールドだが未使用 | GAP |
| `guardrails.maxRetries` | task.ts:50 | 必須フィールドだが未使用 | GAP |

## ソース内 TODO 一覧

| ファイル | 行 | 内容 | 優先度 |
|---------|---|------|--------|
| log.ts | 53 | `traceInfo?: string; // TODO 仮` | LOW |
| log.ts | 56 | `details?: string; // TODO cooperate AI agent` | MEDIUM |
| log.ts | 60 | `resourceIds?: string[]; // TODO 影響がある口座などの関連情報` | LOW |
| log.ts | 69 | `actionType: string; // TODO "analyze", "alert", "remediate"` | LOW |
| log.ts | 72 | `output?: unknown; // TODO AI出力` | LOW |
| error-utils.ts | 5 | `TODO 対象追加。PII検出正規表現（国際対応）` | NA (dead code) |
| error-payload-protocol.ts | 7 | `TODO di堅牢化（ホワイトリスト管理）` | NA (dead code) |

## 型エクスポートの必要性検証

| エクスポート | index.ts行 | 利用者に必要か | 備考 |
|-------------|-----------|--------------|------|
| `SystemEventName` | 161 | ⚠ | 利用者は検知結果にアクセスできない（IngestionResultに含まれない） |
| `DetectionResult` | 161 | ⚠ | 同上 |
| `TaskSeverity` | 158 | ✅ | taskRules定義に必要 |
| `TaskExecutionLevel` | 165 | ✅ | taskRules定義に必要 |
| その他全て | — | ✅ | SDK利用に必要 |

## IngestionResult の情報不足

`IngestionResult` は `{ traceId, hashChainValid, tasksGenerated, masked }` を返すが:
- 処理済みログオブジェクト自体は返されない（`onLogProcessed` callback経由のみ）
- どのイベントが検知されたかは返されない
- マスキングで何が除去されたかは返されない
