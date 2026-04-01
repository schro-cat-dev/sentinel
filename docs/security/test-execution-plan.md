# 脅威テスト実行計画

```yaml
created_at: "2026-04-02"
status: active
```

## 実施済みテスト × 脅威カテゴリ マッピング

| 脅威ID | テストファイル | テスト数 | カバレッジ |
|--------|--------------|---------|-----------|
| A-01 | boundary-validation-hardening.test.ts | 9 | 全文字列フィールド |
| A-02 | boundary-validation-hardening.test.ts, dos-resource-exhaustion.test.ts | 2+45 | agentBackLog含む |
| A-03 | validation-normalizer-exhaustive.test.ts | 159 | 主要フィールド |
| A-04 | prototype-pollution.test.ts, pollution-guard.test.ts | 5+11 | 全入力パス |
| A-05 | custom-detection-rules.test.ts, redos.test.ts | 22+11 | ReDoS + RegExp型検証 |
| A-06 | encoding-bypass.test.ts | 68 | NFC/NFD/homoglyph |
| A-07 | injection-attacks.test.ts | 42 | XSS/SQLi |
| B-01 | state-manipulation.test.ts, instance-lifecycle.test.ts | 55+9 | deepFreeze |
| B-02 | whitelist-security-level.test.ts | 18 | 4レベル全テスト |
| B-03 | config-injection.test.ts | 53 | JSON parse攻撃 |
| B-05 | boundary-validation-hardening.test.ts | 4 | updateCallbacks検証 |
| C-01 | crypto-attacks.test.ts, integrity-chain.test.ts | 38+16 | hash chain |
| C-04 | masking-bypass.test.ts | 18 | 循環参照 |
| C-05 | boundary-validation-hardening.test.ts | 3 | post-shutdown |
| D-03 | config-server-exhaustive.test.ts | 3 | dual-mode |
| E-01 | npm audit | 0件 | ゼロ依存 |

## 未テスト領域（追加実施が必要）

| 脅威ID | 未テスト内容 | 優先度 |
|--------|-------------|--------|
| A-03 | timestamp/logicalClock/triggerAgent の型検証 | LOW |
| D-01 | TLS設定の検証（Go server E2E） | MEDIUM |
| D-02 | 極小timeout設定時の挙動 | LOW |
| E-02 | npm provenance / SBOM | LOW (将来) |
| F-05 | notification provider URL検証 | MEDIUM |
| G-03 | reset()後のセキュリティ状態復元 | LOW (警告済み) |
