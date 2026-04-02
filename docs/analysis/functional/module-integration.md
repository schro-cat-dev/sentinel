# モジュール間連携の完全性

```yaml
analyzed_at: "2026-04-02"
based_on: "3820d07"
status: current
last_updated: "2026-04-02"
```

## パイプラインデータフロー検証

```
Sentinel.ingest(Partial<Log>)
  │  validateLogInput()          ✅ 正常
  │
  ├── [remote] normalizeOnly()   ✅ マスク適用済み（v2修正）
  │     └── transport.send()     ⚠ タイムアウトなし (R-1)
  │
  ├── [local/dual] handle()      ✅ async mutex保護
  │     ├── normalize()          ✅
  │     ├── MaskingService.mask(log全体) ✅ (v2修正)
  │     ├── EventDetector.detect() ✅ SafeLogSubset
  │     ├── TaskGenerator.generate() ✅ __proto__フィルタ
  │     ├── TaskExecutor.dispatch() ✅ ガードレール
  │     ├── IntegritySigner      ✅ timingSafeEqual
  │     └── onLogProcessed       ✅ try-catch
  │
  └── [dual] normalizeOnly()     ⚠ 2度目の正規化（R-5）
        └── transport.send()     ⚠ 失敗は無視
```

## インターフェース vs 実装の整合性

| インターフェース | 定義場所 | 実装 | 問題 |
|----------------|---------|------|------|
| `IIngestionCoordinator` | i-interfaces.ts:4-6 | `IngestionEngine` | ✅ 一致 |
| `ILogNormalizer` | i-interfaces.ts:8-10 | `LogNormalizer` | ⚠ constructorで具象型を受ける |
| `RemoteTransport` | transport.ts:27-42 | ユーザー提供 | ⚠ healthCheck/close未呼出 |

## MaskingService インスタンス vs 静的メソッド問題

| 箇所 | コード | 問題 |
|------|--------|------|
| index.ts:43 | `const masking = new MaskingService()` | インスタンス生成 |
| ingestion-engine.ts:15 | `private readonly masking: MaskingService` | フィールド保持 |
| ingestion-engine.ts:83 | `MaskingService.mask(...)` | **静的メソッド呼出** |

`this.masking` は一度も使われていない。インスタンスが不要なら constructor injection から除外すべき。
ただし将来的にインスタンスメソッド化する可能性を考慮し、DIの一貫性として保持する判断もあり。

## LogNormalizer フィールドパススルー検証

| Log フィールド | normalize()で返されるか | 問題 |
|---------------|----------------------|------|
| traceId | ✅ `raw.traceId \|\| randomUUID()` | |
| spanId | ✅ `raw.spanId` | |
| parentSpanId | ✅ | |
| actorId | ✅ | |
| type | ✅ バリデーション付き | |
| level | ✅ バリデーション付き | |
| timestamp | ✅ フォールバック付き | |
| logicalClock | ✅ | |
| boundary | ✅ | |
| serviceId | ✅ config注入 | |
| origin | ✅ | |
| isCritical | ✅ | |
| message | ✅ `.trim()` | |
| input | ✅ | |
| triggerAgent | ✅ | |
| agentBackLog | ✅ `raw.agentBackLog` | ✅ 修正済 |
| details | ✅ | |
| traceInfo | ✅ `raw.traceInfo` | ✅ 修正済 |
| tags | ✅ | |
| resourceIds | ✅ | |
| previousHash | ✅ | |
| hash | ✅ | |
| signature | ✅ | |
| aiContext | ✅ | |

### ~~重大: agentBackLog / traceInfo がnormalizeで欠落~~ — ✅ 修正済み (BUG-01/02)

`LogNormalizer.normalize()` で `agentBackLog` (line 49) と `traceInfo` (line 48) をパススルー済み。
