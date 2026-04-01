# ErrorRouter ライフサイクル・インスタンス管理

```yaml
status: design
```

## インスタンスライフサイクル

```
Sentinel.initialize(config)
  └→ ErrorRouter.create(config.errorRouting)
       ├→ ErrorClassifier(config.errorRouting.severityConfig)
       ├→ RuleEngine(config.errorRouting.rules)
       └→ ExecutorPool(config.errorRouting.sinks)

Sentinel.shutdown()
  └→ ErrorRouter.shutdown()
       ├→ ExecutorPool.drain()   // 未送信のエラーをフラッシュ
       ├→ AuditSink.close()     // コネクション解放
       └→ DeadLetterQueue.close()
```

## Sentinel統合ポイント

```typescript
// SentinelConfig に追加
interface SentinelConfig {
    // ... 既存フィールド ...

    /** エラールーティング設定（省略時: ログ出力のみ、既存動作維持） */
    errorRouting?: ErrorRoutingConfig;
}

interface ErrorRoutingConfig {
    /** 有効化フラグ（デフォルト: false → 既存emitSafe動作） */
    enabled: boolean;
    /** 分類設定（severity config） */
    severityConfig?: ErrorSeverityConfig;
    /** ルーティングルール */
    rules?: RoutingRule[];
    /** 送信先アダプタ */
    sinks?: {
        audit?: AuditSink;
        deadLetter?: DeadLetterQueue;
    };
}
```

## パイプライン統合（non-blocking）

```
IngestionEngine.emitSafe()
  ├─→ catch(error)
  │     ├─→ if errorRouter.enabled:
  │     │     └─→ errorRouter.route(error, context)  // 非同期、fire-and-forget
  │     │           └─→ .catch(console.error)         // 最終防壁
  │     └─→ else:
  │           └─→ onError?.(error, context)           // 既存動作
  └─→ パイプラインは常に継続
```

**ゼロオーバーヘッド保証:**
- `errorRouting.enabled = false`（デフォルト）の場合、ErrorRouterのコードパスに入らない
- `enabled = true` でもルーティングは非同期。`ingest()` のレイテンシに影響しない
- Promise.catch で最終防壁。ルーティング失敗がパイプラインに伝播しない

## メモリ管理

| リソース | ライフサイクル | 解放タイミング |
|---------|-------------|--------------|
| ErrorClassifier | Sentinel存続期間 | shutdown() |
| RuleEngine | Sentinel存続期間 | shutdown() |
| AuditSink接続 | Sentinel存続期間 | shutdown() → close() |
| DLQ接続 | Sentinel存続期間 | shutdown() → close() |
| 分類中間オブジェクト | 1エラーごと | 即時GC |
| RoutingDecision[] | 1エラーごと | 即時GC |

## セキュリティ

- ErrorRoutingConfig はdeepFreezeの対象（config全体がfreeze済み）
- ルーティングルールの `kind_pattern` はReDoS検証する（EventDetector.messagePatternと同じ）
- AuditSink/DLQの認証情報はconfigに含めず、環境変数経由でアダプタ内部で解決
- エラーペイロードのPIIは `maskPiiContext()` で除去してから送信
