# 可観測性・ログ・メトリクス

```yaml
analyzed_at: "2026-04-02"
based_on: "3227fe1"
status: current
```

## 所見一覧

### O-1: ログ・メトリクス基盤が存在しない — ✅ 対応済み (OBS-03)

`SentinelLogger` インターフェースを導入済み（`sentinel-config.ts:12-15`）。`config.logger` でDI可能。
`SentinelMetrics` / `SentinelTracer` インターフェースも追加済み。パイプラインの各ステージでメトリクス・トレーシング出力が可能。

### O-2: エラーの無言swallow — ✅ 対応済み (OBS-01)

`onError` コールバック + `ErrorRouter` + `ConsoleAuditSink` により構造化出力。`emitSafe` でのswallowも `errorRouter` 経由で記録される。

### O-3: onTaskGenerated / onTaskDispatched が未接続 — ✅ 対応済み (BUG-03/04)

`ingestion-engine.ts:159-161` で `emitSafe` 経由でコールバック呼出実装済み。

### O-4: エラーが構造化されていない — ✅ 対応済み (O-4)

`SentinelError(layer, operation, cause)` を導入。パイプライン内部エラーは構造化済み。`ErrorPayloadProtocol` は `ConsoleAuditSink` 経由でパイプラインに接続済み。

## IngestionResult の情報量

現在の返却値:
```typescript
{ traceId, hashChainValid, tasksGenerated, masked, detection, transportError? }
```

- ✅ `detection` フィールド追加済み（eventName + priority）（OBS-02）
- 処理済みログオブジェクトは `onLogProcessed` callback 経由（設計上の意図）
- マスキング適用レポート — 未実装
- パイプライン処理時間 — `tracer.onPipelineEnd` で提供
