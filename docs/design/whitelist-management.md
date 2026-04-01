# ホワイトリスト管理方針

```yaml
created_at: "2026-04-01"
updated_at: "2026-04-01"
status: implemented
branch: feat/whitelist-validation
```

## 概要

自由文字列で受け付けている値のうち、有限の許容値セットが定義できるものをホワイトリスト管理し、不正値を早期に拒否する。モジュラーなアダプタパターンで各ドメインのホワイトリストを分離し、設定でドメイン単位の有効/無効切替とセキュリティレベル制御を提供する。

## 2階層構造

### 1階層目: 適用箇所（パイプラインステージ）

各ホワイトリストドメインが、対応するパイプラインコンポーネントに到達してバリデーションが効く。

| ドメイン | 適用先コンポーネント | 検証対象フィールド |
|---------|---------------------|-------------------|
| `security` | EventDetector, SeverityClassifier | `eventName`, `detectionPriority` |
| `task` | TaskGenerator, TaskExecutor | `actionType`, `severity`, `executionLevel` |
| `privacy` | MaskingService | `piiCategory` |

### 2階層目: 各ドメイン内のフィールド定義

一元管理ディレクトリ: `src/validation/whitelists/`

| ファイル | フィールド | ソースオブトゥルース |
|---------|-----------|---------------------|
| `security-whitelist.ts` | `eventName` (4値), `detectionPriority` (3値) | `SystemEventMap` keys |
| `task-whitelist.ts` | `actionType` (6値), `severity` (5値), `executionLevel` (4値) | `TASK_ACTION_TYPES`, `TASK_SEVERITIES` |
| `privacy-whitelist.ts` | `piiCategory` (8値) | `MaskingService.PII_PATTERNS` keys |

## セキュリティレベル設定

```typescript
whitelist?: {
    level?: "strict" | "standard" | "permissive" | "off";
    enabledDomains?: ("security" | "task" | "privacy")[];
    extensions?: Record<string, string[]>;
}
```

| レベル | 不正値の挙動 | extensions | 用途 |
|--------|-------------|-----------|------|
| `strict` | エラー（即座に拒否） | **無視** | 本番環境、セキュリティ最優先 |
| `standard` | エラー（即座に拒否） | 有効 | 通常運用（デフォルト） |
| `permissive` | 警告のみ（logger.warn） | 有効 | 移行期間、段階的導入 |
| `off` | 検証なし | — | 開発・デバッグ（本番非推奨） |

堅牢性 vs 柔軟性のトレードオフを設定で明示的に制御する。

## ルーティングフロー

```
Sentinel.initialize(config)
  └→ validateConfigWhitelists(config)
       ├→ level判定 ("off"→スキップ)
       ├→ enabledDomains でドメイン選択
       ├→ WhitelistRegistry 構築 (定義 + extensions)
       └→ 全ルールを検証
            ├→ detectionRules[].eventName, priority
            ├→ taskRules[].eventName, severity, actionType, executionLevel
            └→ masking.rules[].category (PII_TYPE)

Sentinel.onTaskAction(actionType, handler)
  └→ whitelistRegistry.validate("actionType", actionType)
```

## テストカバレッジ

| テストファイル | テスト数 | 検証内容 |
|--------------|---------|---------|
| `whitelist-registry.test.ts` | 20 | Registry構築、合成、拡張、セキュリティ |
| `config-validator.test.ts` | 22 | 全フィールドの正常/異常、ドメイン切替、拡張値 |
| `whitelist-definitions.test.ts` | 10 | 各定義の値がソースオブトゥルースと一致 |
| `whitelist-config-yaml.test.ts` | 9 | YAML/JSON設定シミュレーション、設定切替 |
| `whitelist-security-level.test.ts` | 18 | strict/standard/permissive/off の各挙動 |
| `whitelist-routing-e2e.test.ts` | 20 | 全パイプラインステージへの到達検証 |
| **合計** | **99** | |
