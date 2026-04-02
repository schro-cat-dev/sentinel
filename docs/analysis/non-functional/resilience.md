# 耐障害性・フォールトトレランス

```yaml
analyzed_at: "2026-04-01"
based_on: "7bf6f11"
status: current
last_updated: "2026-04-02"
```

## 所見一覧

### ~~R-1: transport.send() にタイムアウトなし~~ ✅ 対策済み (RES-01)

`sendWithTimeout()` (index.ts) で `Promise.race` + `setTimeout` による30秒デフォルトタイムアウトを実装。`TransportConfig.timeoutMs` で設定可能。タイムアウト時は `SentinelError("transport", "timeout", ...)` をスロー。

### ~~R-2: ハンドラ失敗で後続ハンドラが中断~~ ✅ 対策済み

`invokeHandlers()` (task-executor.ts) で全ハンドラを実行し、各ハンドラの例外を個別に catch してエラーを集約。1つ目が失敗しても2つ目以降は実行される。集約エラーは `SentinelError("task", "invokeHandlers", ...)` としてスロー。

### ~~R-3: dualモードで2度正規化~~ ✅ 対策済み (RES-02)

`IngestionEngine.getLastProcessedLog()` で `handle()` の処理済みログをキャッシュ。dual モードでは `normalizeOnly()` の代わりにキャッシュされたログを送信し、traceId/timestamp の不一致を防止。

### ~~R-4: リモート送信のサーキットブレーカーなし~~ ✅ 対策済み

`CircuitBreaker` (transport/circuit-breaker.ts) を導入。連続失敗がしきい値（デフォルト5）に達すると open 状態に遷移し、cooldown（デフォルト30秒）中はリクエストを即座に拒否。cooldown 後に half-open で1回試行し、成功で closed に戻る。`TransportConfig.circuitBreaker` で設定可能。

### ~~R-5: normalizeOnly() 失敗がfallbackToLocalに掛からない~~ ✅ 対策済み

remote モードの `ingest()` で `normalizeOnly()` を try/catch の外に分離。正規化エラーは transport エラーとは別にそのまま伝搬する。transport エラーのみが `fallbackToLocal` の対象となり、`IngestionResult.transportError` に正しく分類される。
