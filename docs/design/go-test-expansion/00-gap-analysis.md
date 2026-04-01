# Go Server テスト拡充 ギャップ分析

```yaml
created_at: "2026-04-02"
status: remediation
current_tests: 741
target_tests: 850+
```

## 重大ギャップ 10件（優先度順）

### P0: セキュリティコントロールの未テスト

| # | 問題 | 影響 | 対策 |
|---|------|------|------|
| 1 | RateLimitUnaryInterceptor テストゼロ | レートリミット回避可能かどうか不明 | interceptor単体テスト + バースト/並行テスト |
| 2 | AuthUnaryInterceptor テストゼロ | 認証回避可能かどうか不明 | interceptor単体テスト + 不正トークン/メタデータテスト |

### P1: データ整合性の未テスト

| # | 問題 | 影響 | 対策 |
|---|------|------|------|
| 3 | Store障害時のdegraded modeテストゼロ | FailOnPersistError分岐が未検証 | mock store + 各段階のエラー注入テスト |
| 4 | 通知アダプタ障害テストゼロ | パイプライン内notify失敗の挙動不明 | mock notifier + 失敗時のエラー伝播テスト |

### P2: ライフサイクル・パフォーマンス

| # | 問題 | 影響 | 対策 |
|---|------|------|------|
| 5 | graceful shutdown テストゼロ | in-flight request処理の保証なし | gRPC server lifecycle テスト |
| 6 | メモリベンチマークゼロ | メモリリーク・リグレッション検知不可 | b.ReportAllocs() + 並行ベンチマーク |

### P3: 侵入経路

| # | 問題 | 影響 | 対策 |
|---|------|------|------|
| 7 | Config injection（YAML/env var）テストゼロ | 設定改竄の検知不可 | 悪意のあるYAML/env入力テスト |
| 8 | Unicode/encoding bypass テストゼロ | PIIマスキング回避可能性 | homoglyph/zero-width/NFC/NFDテスト |
| 9 | gRPC metadata injection テストゼロ | ヘッダ偽装の検知不可 | 不正metadata/multiple key テスト |
| 10 | 情報漏洩テストゼロ | エラーメッセージにパス/設定値漏洩 | エラーレスポンス内容検証テスト |

## トレードオフ判断

| 項目 | 実装する | 理由 |
|------|---------|------|
| Rate limiter テスト | YES | セキュリティコントロールは必須 |
| Auth interceptor テスト | YES | 同上 |
| Store degraded mode | YES | データ整合性は本番要件 |
| Graceful shutdown | YES | 運用安全性 |
| Memory benchmark | YES（基本のみ） | ReportAllocs追加は低コスト |
| Config injection | YES（主要パターン） | YAML billion-laughsは除外（Go yaml.v3は安全） |
| TLS テスト | NO | テスト環境での証明書管理が複雑。ドキュメントで対応 |
| Malformed protobuf | NO | gRPCフレームワークが処理。低リスク |
