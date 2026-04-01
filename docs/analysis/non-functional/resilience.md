# 耐障害性・フォールトトレランス

```yaml
analyzed_at: "2026-04-01"
based_on: "b14d263"
status: current
```

## 所見一覧

### R-1: transport.send() にタイムアウトなし [CRITICAL]

**箇所:** `src/index.ts:108, 122`

remote/dualモードで `transport.send()` を await するが、タイムアウト・AbortController・デッドラインが一切ない。TCPコネクションがハングした場合、`ingest()` は永久にresolveしない。

**影響:** remoteモードで呼び出し元のスレッドが無期限ブロック。dualモードでは未解決Promiseが蓄積。

**改善案:** `Promise.race` でタイムアウトを実装:
```typescript
const timeout = new Promise((_, reject) =>
  setTimeout(() => reject(new Error("Transport timeout")), 30000)
);
await Promise.race([transport.send(log), timeout]);
```

### R-2: ハンドラ失敗で後続ハンドラが中断 [HIGH]

**箇所:** `src/core/task/task-executor.ts:89-91`

`invokeHandlers()` で最初の失敗でループが停止。3つのハンドラのうち1番目が失敗すると2番目と3番目は実行されない。

**改善案:** 全ハンドラを実行し、エラーを集約して返す。

### R-3: dualモードで2度正規化 [MEDIUM]

**箇所:** `src/index.ts:117-127`

`handle(log)` 内で1度目の正規化、`normalizeOnly(log)` で2度目。`randomUUID()` や `Date.now()` の呼出で異なる `traceId` / `timestamp` が生成される。ローカルとリモートで異なるログが生まれる。

**改善案:** `handle()` の処理済みログを `normalizeOnly()` の代わりに送信。

### R-4: リモート送信のサーキットブレーカーなし [MEDIUM]

**箇所:** `src/index.ts:105-114`

リモート障害が継続しても毎回送信を試みる。ネットワーク障害時にレイテンシが積み上がる。

### R-5: normalizeOnly() 失敗がfallbackToLocalに掛からない [MEDIUM]

**箇所:** `src/index.ts:106-108`

```typescript
try {
    const normalized = this.engine.normalizeOnly(log); // ← ここで例外
    return await this.transportConfig.transport.send(normalized);
} catch (err) {
    if (this.transportConfig.fallbackToLocal) { // ← normalizeOnly例外もここに来る
```

`normalizeOnly()` が投げた例外もcatchに入るが、これは正規化の失敗であってtransportの失敗ではない。フォールバックすべきかは判断が分かれる。
