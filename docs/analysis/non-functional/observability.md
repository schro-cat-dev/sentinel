# 可観測性・ログ・メトリクス

```yaml
analyzed_at: "2026-04-01"
based_on: "b14d263"
status: current
```

## 所見一覧

### O-1: ログ・メトリクス基盤が存在しない [HIGH]

SDK全体で構造化ログ出力がゼロ。唯一のログは:
- `masking-service.ts:183` — `console.warn` でマスキングルール失敗
- `error-utils.ts:134` — `console.error` で監査ログ（dead code）

利用者が観測できない項目:
- パイプラインの各ステージのレイテンシ
- ルールマッチ率
- ハッシュチェーン長・整合性
- エラー率（カテゴリ別）
- マスキングされたフィールド数

**改善案:** SDKレベルのロガーインターフェースを導入し、利用者が注入可能にする:
```typescript
interface SentinelLogger {
  debug(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
}
```

### O-2: エラーの無言swallow [HIGH]

| 箇所 | コード | 影響 |
|------|--------|------|
| index.ts:123 | `catch { }` (dualモードremote失敗) | 利用者はリモート障害を知る手段がない |
| ingestion-engine.ts:117 | `catch { }` (onLogProcessed例外) | コールバックの不具合が検出不能 |

**改善案:** swallow時にオプショナルなエラーコールバック (`onError?`) を呼ぶ。

### O-3: onTaskGenerated / onTaskDispatched が未接続 [MEDIUM]

`SentinelConfig` に宣言されたコールバックが呼ばれないため、利用者はタスク生成・ディスパッチのイベントを観測できない。`IngestionResult.tasksGenerated` からディスパッチ結果は取れるが、生成時のフックがない。

### O-4: エラーが構造化されていない [MEDIUM]

`ValidationError` は `field` プロパティを持つが、パイプライン内部のエラー（`LogNormalizer` の `new Error(...)` など）はプレーンな `Error` オブジェクト。`ErrorPayloadProtocol` が `shared/errors/` に定義されているが未使用。

## IngestionResult の情報量

現在の返却値:
```typescript
{ traceId, hashChainValid, tasksGenerated, masked }
```

不足している情報:
- 処理済みログオブジェクト
- 検知されたイベント（eventName, priority）
- マスキング適用レポート
- パイプライン処理時間
