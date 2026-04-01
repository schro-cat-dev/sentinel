# 修正計画 + TDDテストケース

```yaml
status: remediation
```

## TS SDK 修正 (4件)

### F-08: RegExp g/y フラグ拒否 (event-detector.ts)

テストケース:
1. `/pattern/g` → エラー「messagePattern must not have global/sticky flag」
2. `/pattern/y` → 同上
3. `/pattern/gi` → 同上
4. `/pattern/i` → OK
5. `/pattern/` → OK

### F-14: errorRouting.rules ホワイトリスト検証 (config-validator.ts)

テストケース:
6. severity="INVALID" → ValidationError
7. destination="INVALID" → ValidationError
8. action="INVALID" → ValidationError
9. 正常なルール → OK
10. errorRouting未設定 → スキップ（OK）

### F-15: detectionRules.conditions ホワイトリスト検証 (config-validator.ts)

テストケース:
11. logTypes=["INVALID"] → ValidationError
12. logTypes=["SECURITY", "INVALID"] → ValidationError（部分不正）
13. origin="INVALID" → ValidationError
14. logTypes=["SECURITY", "COMPLIANCE"] → OK
15. origin="SYSTEM" → OK
16. conditions未設定 → スキップ（OK）

### F-01: projectName をパイプラインで使用 (log-normalizer.ts)

テストケース:
17. projectName がIngestionResultまたはLog内に反映される

## Go Server 修正 (3件)

### F-03: detection_rules struct追加 (config.go)

テストケース:
18. detection_rules YAMLが正しくパースされる
19. 不正なevent_name → validate()エラー
20. 不正なpriority → validate()エラー

### F-05: error_routing.rules validate() (config.go)

テストケース:
21. 不正なseverity → エラー
22. 不正なdestination → エラー
23. 正常なルール → OK

### F-10: env var enum validation (config.go)

テストケース:
24. SENTINEL_RESPONSE_DEFAULT_STRATEGY=INVALID → エラー
