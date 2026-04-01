# TDD実施計画

```yaml
status: implemented
estimated_tests: 45
```

## テスト構成

```
tests/unit/error-routing/
├── error-classifier.test.ts     # 分類ロジック (10)
├── routing-engine.test.ts       # ルール評価 (10)
├── executor-pool.test.ts        # アダプタ実行 (8)
├── error-router.test.ts         # オーケストレーション統合 (7)
└── sinks/
    └── default-sinks.test.ts    # デフォルト実装 (4)

tests/security/advanced/
└── error-routing-penetration.test.ts  # 侵入経路 (6)
```

## テスト詳細

### error-classifier.test.ts (10テスト)

| # | テスト | 種別 |
|---|-------|------|
| 1 | TransportTimeout → kind="TransportTimeout", severity=WARNING | 正常系 |
| 2 | ConnectionRefused → kind="TransportConnectionRefused", severity=CRITICAL | 正常系 |
| 3 | Handler例外 → kind="HandlerException", severity=WARNING | 正常系 |
| 4 | ValidationError → kind="ValidationFailure", severity=INFO | 正常系 |
| 5 | 不明なエラー → kind="Unknown", severity=WARNING | 異常系 |
| 6 | カスタムSeverityConfig → 設定通りに分類 | 正常系 |
| 7 | error.messageがnull/undefined → クラッシュしない | エッジ |
| 8 | 非Errorオブジェクト → 安全にラップ | エッジ |
| 9 | traceId/layer/operation がmetaに正しく伝播 | 正常系 |
| 10 | 分類自体が例外 → "ClassificationError"として返す | 異常系 |

### routing-engine.test.ts (10テスト)

| # | テスト | 種別 |
|---|-------|------|
| 1 | CRITICAL → 3 decisions (task + notification + audit) | 正常系 |
| 2 | WARNING + Transport → 2 decisions (DLQ + audit) | 正常系 |
| 3 | INFO → 1 decision (log) | 正常系 |
| 4 | カスタムルール設定 → デフォルト上書き | 正常系 |
| 5 | ルールなし → デフォルト(log + record) | 異常系 |
| 6 | first-match-wins → 先頭ルールのみ適用 | 正常系 |
| 7 | kind_pattern RegExp マッチ | 正常系 |
| 8 | kind_pattern ReDoS → 検証時に拒否 | ペネトレーション |
| 9 | 空のdecisions配列 → 何もしない | エッジ |
| 10 | metadata にprototype pollution → 安全 | ペネトレーション |

### executor-pool.test.ts (8テスト)

| # | テスト | 種別 |
|---|-------|------|
| 1 | AuditSink.send() 成功 → result.success=true | 正常系 |
| 2 | AuditSink.send() 失敗 → フォールバック → console.error | 異常系 |
| 3 | DLQ.enqueue() 成功 | 正常系 |
| 4 | 全アダプタ同時失敗 → console.error、パイプライン影響なし | 異常系 |
| 5 | タイムアウト（アダプタが永遠に応答しない） → 強制完了 | エッジ |
| 6 | 100エラー同時 → 全て非同期処理 | パフォーマンス |
| 7 | PII除去されたペイロードが送信される | セキュリティ |
| 8 | アダプタのエラーがErrorRouterに再投入されない | 無限ループ防止 |

### error-router.test.ts (7テスト)

| # | テスト | 種別 |
|---|-------|------|
| 1 | enabled=true → 分類→ルーティング→実行の全フロー | 統合 |
| 2 | enabled=false → 既存emitSafe動作（onError呼出し） | 後方互換 |
| 3 | shutdown中のエラー → 安全に無視 | エッジ |
| 4 | パイプラインのレイテンシに影響しない（非同期） | パフォーマンス |
| 5 | depth=1 で再帰防止 | 無限ループ防止 |
| 6 | resetState()でリソース解放 | ライフサイクル |
| 7 | Sentinel.initialize()→ErrorRouter生成→shutdown()→解放の全サイクル | 統合 |

### error-routing-penetration.test.ts (6テスト)

| # | テスト | 種別 |
|---|-------|------|
| 1 | ErrorPayloadProtocol.meta.contextにPII → maskPiiContextで除去 | セキュリティ |
| 2 | kind_patternにReDoSパターン → 初期化時に拒否 | ペネトレーション |
| 3 | metadata に __proto__ → Object.prototype汚染なし | ペネトレーション |
| 4 | AuditSinkが悪意のあるデータ返却 → 安全に無視 | ペネトレーション |
| 5 | classifyError に巨大errorオブジェクト → サイズ制限で切り捨て | DoS |
| 6 | 同時1000エラー → メモリ爆発しない | DoS |

## 実施順序

1. types.ts（型定義のみ）
2. error-classifier.test.ts → error-classifier.ts
3. routing-engine.test.ts → routing-engine.ts
4. executor-pool.test.ts → executor-pool.ts + sinks/
5. error-router.test.ts → error-router.ts
6. ingestion-engine.ts 修正（emitSafe統合）
7. error-routing-penetration.test.ts
8. 全体リグレッションテスト
