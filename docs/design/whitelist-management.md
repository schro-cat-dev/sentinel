# ホワイトリスト管理方針

```yaml
analyzed_at: "2026-04-01"
based_on: "7bc95d0"
status: current
```

## 概要

自由文字列で受け付けている値のうち、有限の許容値セットが定義できるものをホワイトリスト管理し、不正値を早期に拒否する。型レベル（TypeScript union type）とランタイムレベル（Set/配列チェック）の両方で制約する。

## 現状分析と対応方針

### 既にホワイトリスト管理されているもの

| 値 | 型定義 | ランタイム検証 | 管理場所 |
|----|--------|--------------|---------|
| `LogType` | union type (`"BUSINESS-AUDIT" \| ...`) | `VALID_LOG_TYPES` 配列 | log.ts + log-validator.ts |
| `LogLevel` | union type (`1 \| 2 \| ... \| 6`) | `VALID_LOG_LEVELS` 配列 | log.ts + log-validator.ts / log-normalizer.ts |
| `origin` | union type (`"SYSTEM" \| "AI_AGENT"`) | `VALID_ORIGINS` 配列 | log.ts + log-validator.ts |
| `environment` | union type (5値) | TypeScript型のみ | sentinel-config.ts |
| `TransportMode` | union type (`"local" \| "remote" \| "dual"`) | TypeScript型のみ | transport.ts |
| `TaskPriority` | union type (`1 \| 2 \| 3 \| 4 \| 5`) | TypeScript型のみ | task.ts |
| `TaskSeverity` | union type (5値) | TypeScript型のみ | task.ts |
| `TaskExecutionLevel` | union type (4値) | ランタイム switch 分岐 | task.ts + task-executor.ts |
| `TaskDispatchStatus` | union type (4値) | TypeScript型のみ | task.ts |

### ホワイトリスト管理すべきもの（未対応）

| 値 | 現状 | リスク | 対応方針 |
|----|------|--------|---------|
| **`TaskActionType`** | 型は union だがランタイムは `string` で受付 | 未定義アクションのハンドラ登録、ルール設定のタイポが無言で通過 | `registerHandler` / `onTaskAction` でホワイトリストチェック |
| **`TaskRule.eventName`** | 型は `string` | 存在しないイベント名のルールが無言で無視される | `SystemEventName` union から生成したSetでチェック |
| **`MaskingRule.PII_TYPE.category`** | 型は union (`"CREDIT_CARD" \| ...`) だが `getPiiPattern()` は `string` で受付 | 存在しないカテゴリが無言でスキップ | `getPiiPattern` で存在チェック + 警告 |
| **`NotifyRoutingRule.provider`** | `string` | 存在しないプロバイダ名が無言で無視 | 有効プロバイダ名のSetでチェック |
| **`TaskRule.severity`** | 型は `TaskSeverity` だがランタイム未検証 | 無効な重大度でルールが永久にマッチしない | `TASK_SEVERITIES` constでチェック |
| **`TaskRule.executionLevel`** | 型は `TaskExecutionLevel` だがランタイム未検証 | default分岐でskippedになる | `Set`でチェック |

## 実装計画

### Phase 1: 定数のexport（型とランタイムの統一）

```typescript
// src/types/task.ts に既存:
export const TASK_ACTION_TYPES = [
    "AI_ANALYZE", "AUTOMATED_REMEDIATE", "SYSTEM_NOTIFICATION",
    "EXTERNAL_WEBHOOK", "KILL_SWITCH", "ESCALATE",
] as const;

// 追加: ランタイム検証用Set
export const VALID_ACTION_TYPES = new Set(TASK_ACTION_TYPES);
export const VALID_SEVERITIES = new Set(TASK_SEVERITIES);
export const VALID_EXECUTION_LEVELS = new Set(["AUTO", "SEMI_AUTO", "MANUAL", "MONITOR"] as const);
```

### Phase 2: バリデーション追加箇所

| 箇所 | チェック内容 | 違反時の動作 |
|------|------------|------------|
| `TaskExecutor.registerHandler(actionType)` | `VALID_ACTION_TYPES.has(actionType)` | 警告ログ（登録は許可、将来のカスタムアクション対応のため） |
| `Sentinel.onTaskAction(actionType)` | 同上 | 同上 |
| `TaskGenerator` constructor | `rule.eventName` が `SystemEventName` に含まれるか | 警告ログ |
| `TaskGenerator` constructor | `rule.severity` が `VALID_SEVERITIES` に含まれるか | エラー throw |
| `TaskGenerator` constructor | `rule.executionLevel` が `VALID_EXECUTION_LEVELS` に含まれるか | エラー throw |
| `MaskingService.getPiiPattern(category)` | `PII_PATTERNS` にキーが存在するか | 警告ログ（logger DI経由） |
| Go config.go `validate()` | `notify.routing[].provider` が有効値か | エラー return |

### Phase 3: ドキュメント・テスト

- 各ホワイトリストの有効値一覧をドキュメント化
- 無効値が警告/エラーになるテストを追加
- 将来のカスタム値拡張パスを文書化（registerHandler は警告のみで拒否しない理由）

## 設計判断

### なぜ registerHandler は拒否しないか

SDKの利用者がカスタムアクションタイプを定義する可能性がある。例えば `sentinel.onTaskAction("MY_CUSTOM_ACTION", handler)` のようなケース。これを拒否すると拡張性が失われる。代わりに警告を出し、組込みアクションタイプでない場合に利用者に注意を促す。

### なぜ TaskRule.eventName は拒否するか

`EventDetector` が生成するイベントは `SystemEventMap` のキーに限定される。存在しないイベント名のルールは永久にマッチせず、利用者の意図しない無動作を引き起こす。これは設定のバグであり、早期に検出すべき。

### なぜ getPiiPattern は警告のみか

カスタムPIIカテゴリの将来拡張を考慮。`PII_PATTERNS` に存在しないカテゴリは単にスキップされるが、利用者のタイポの可能性があるため警告を出す。
