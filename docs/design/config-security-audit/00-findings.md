# YAML/Config セキュリティ監査 全発見事項

```yaml
audited_at: "2026-04-02"
scope: TS SDK + Go Server
findings: 11
```

## HIGH (1件)

### F-03: Go server `detection_rules` YAML がパース不能（struct未定義）

- **ファイル:** `packages/server/config/config.go` — Config structに`detection_rules`フィールドなし
- **YAML:** `packages/server/config/sentinel.yaml:79` — `detection_rules: []` + コメント例あり
- **影響:** YAMLに設定してもGo YAMLパーサが無視。ユーザーのルールが無言で消失
- **対策:** Config structに`DetectionRules []DetectionRuleConfig \`yaml:"detection_rules"\`` 追加 + validate()で検証

## MEDIUM (7件)

### F-01: `projectName` がdead config（必須だが未使用）

- **ファイル:** `src/configs/sentinel-config.ts:46`, `src/index.ts`
- **影響:** ユーザーが必ず設定するが値は使われない
- **対策:** LogNormalizer/IngestionResultに伝播させるか、requiredから外す。今回はLogNormalizerで使用

### F-04: Go `error_routing` がパースされるがパイプライン未接続

- **ファイル:** `packages/server/config/config.go:26`, `packages/server/cmd/server/main.go`
- **影響:** `error_routing.enabled: true` が無効
- **対策:** ドキュメントに「Go Server側は将来実装」と明記（既にdocs/design/error-routing/に記載済み）

### F-05: Go `error_routing.rules` がvalidate()で未検証

- **ファイル:** `packages/server/config/config.go:validate()`
- **影響:** 不正なseverity/destination/action値が通過
- **対策:** validate()にenum検証追加

### F-08: RegExp `/g` `/y` フラグで検知が非決定的

- **ファイル:** `src/core/detection/event-detector.ts:147`
- **影響:** `.test()` がlastIndexを進め、交互にtrue/false
- **対策:** validateCustomRules()でg/yフラグ拒否

### F-10: Go env vars `SENTINEL_RESPONSE_DEFAULT_STRATEGY` 等が未検証

- **ファイル:** `packages/server/config/config.go:400-402`
- **影響:** 任意文字列が受け入れられる
- **対策:** validate()にenum検証追加

### F-14: `errorRouting.rules` がTS SDK ホワイトリスト検証をバイパス

- **ファイル:** `src/validation/config-validator.ts:69-92`
- **影響:** strict モードでも errorRouting のseverity/destination/action が未検証
- **対策:** config-validator.tsにerrorRouting.rules検証追加

### F-15: `detectionRules.conditions.logTypes/origin` が未検証

- **ファイル:** `src/validation/config-validator.ts:70-75`
- **影響:** 不正なlogType/originが無言で不一致（ルール不発）
- **対策:** conditions.logTypes[], conditions.originをホワイトリスト検証

## LOW (3件)

### F-02: `security.signingKeyId` がdead config

- **対策:** ドキュメントに「将来のキーローテーション用」と明記

### F-12: Go HMAC key が hash chain無効時に未検証

- **対策:** 許容（設計通り）。ドキュメント注記

### F-13: Go config path が未サニタイズ

- **対策:** CLIフラグ経由のみ（シェルアクセス前提）。低リスクだがドキュメント注記
