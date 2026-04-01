# モジュール構成・責務・データフロー

```yaml
status: design
```

## ファイル構成

```
src/
├── error-routing/
│   ├── error-router.ts           # オーケストレーター（制御層）
│   ├── error-classifier.ts       # エラー → ErrorPayloadProtocol + severity
│   ├── routing-engine.ts         # ルール評価 → RoutingDecision[]
│   ├── executor-pool.ts          # Decision → アダプタ実行
│   ├── types.ts                  # RoutingRule, RoutingDecision, ErrorRoutingConfig
│   └── sinks/                    # アダプタ実装
│       ├── console-audit-sink.ts # デフォルト: console.error出力
│       ├── noop-dead-letter.ts   # デフォルト: 何もしない
│       └── index.ts              # barrel export
│
├── shared/utils/error-utils.ts   # 既存（変更なし）: classifyError, serializeForAudit
├── shared/errors/error-payload-protocol.ts  # 既存（変更なし）
│
└── core/engine/ingestion-engine.ts  # 変更: emitSafe()にErrorRouter委任を追加
```

## モジュール間依存

```
ingestion-engine.ts
  │ (optional)
  └─→ error-router.ts
        ├─→ error-classifier.ts
        │     └─→ shared/utils/error-utils.ts (classifyError)
        │     └─→ shared/errors/error-payload-protocol.ts (型)
        ├─→ routing-engine.ts
        │     └─→ types.ts (RoutingRule, RoutingDecision)
        └─→ executor-pool.ts
              ├─→ types.ts (AuditSink, DeadLetterQueue interfaces)
              ├─→ shared/utils/error-utils.ts (serializeForAudit, maskPiiContext)
              └─→ sinks/ (デフォルト実装)
```

**依存方向: 常に上→下。循環なし。**

## データフロー詳細

```
① Error発生（emitSafe catch内）
   │
   │ { error: Error, context: string, traceId?: string }
   │
   ▼
② ErrorClassifier.classify()
   │
   │ ErrorPayloadProtocol {
   │   kind: "TransportTimeout",
   │   code: "TRANSPORT_TIMEOUT",
   │   message: "Transport timeout after 30000ms",
   │   meta: {
   │     traceId: "abc-123",
   │     layer: "transport",
   │     operation: "dual-send",
   │     context: { mode: "dual", timeoutMs: 30000 }
   │   }
   │ }
   │ + severity: "WARNING"
   │
   ▼
③ RoutingEngine.evaluate()
   │
   │ RoutingDecision[] = [
   │   { destination: "dead_letter", action: "retry", priority: 3, metadata: { queue: "..." } },
   │   { destination: "audit_sink", action: "record", priority: 3, metadata: {} },
   │ ]
   │
   ▼
④ ExecutorPool.executeAll()
   │
   │ ┌─→ DeadLetterQueue.enqueue(payload, metadata) → Promise<void>
   │ └─→ AuditSink.send(payload) → Promise<void>
   │
   ▼
⑤ ExecutionResult[] (非同期、パイプライン非ブロック)
```

## Go Server統合

Go Server側では同じ概念をGoで実装:

```
packages/server/internal/error-routing/
├── router.go           # ErrorRouter (Go版)
├── classifier.go       # 分類ロジック
├── engine.go           # ルール評価
├── executor.go         # アダプタ実行
└── sinks/
    ├── datadog.go       # Datadog Events API
    ├── sentry.go        # Sentry SDK
    ├── cloudwatch.go    # CloudWatch Logs
    ├── sqs.go           # SQS Dead Letter Queue
    └── log.go           # slog出力（デフォルト）
```

Go側のパイプライン（pipeline.go）では:
- 既存の `slog.Error()` 呼び出し箇所を ErrorRouter.Route() に差し替え
- 既存の notify/notifier.go はそのまま維持（通知はErrorRouter経由でも直接でも使える）
- response/orchestrator.go のエラーハンドリングも ErrorRouter に統合可能

## 定性チェック

| 観点 | 判定 | 根拠 |
|------|------|------|
| 責務分離 | OK | 分類/ルーティング/実行が明確に分離。各1責務 |
| 依存方向 | OK | 上→下の一方向。循環なし |
| テスタビリティ | OK | 各モジュール単体テスト可能。アダプタはDI |
| 拡張性 | OK | 新アダプタはインターフェース実装のみ。既存コード変更不要 |
| 堅牢性 | OK | 3重防壁で無限ループ防止。最終フォールバックは常にconsole.error |
| オーバーヘッド | OK | enabled=false で分岐1つ。enabled=true でも非同期non-blocking |
| 後方互換 | OK | errorRouting未設定時は既存動作（emitSafe → onError → console.error） |
| セキュリティ | OK | PII除去、ReDoS検証、認証情報のconfig分離 |
