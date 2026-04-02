# インスタンス管理 詳細監査報告

```yaml
audited_at: "2026-04-02"
scope: Sentinel singleton lifecycle, mutable state, concurrency, GC
```

## 1. Sentinel シングルトン ライフサイクル

```
initialize(config)
  ├→ validateConfigWhitelists(config) → WhitelistRegistry
  ├→ new Sentinel(config, registry, options)
  │   ├→ LogNormalizer(serviceId)
  │   ├→ IntegritySigner()
  │   ├→ EventDetector(detectionRules)      ← 入力配列未コピー
  │   ├→ TaskGenerator(taskRules)            ← 入力配列未コピー
  │   ├→ TaskExecutor()
  │   └→ IngestionEngine({...deps})
  └→ Sentinel.instance = new instance

shutdown()
  ├→ if (isShutdown) return                  ← 冪等性ガード (3.2 対応済み)
  ├→ isShutdown = true
  ├→ transport.close()                       ← try/catch でベストエフォート
  ├→ taskExecutor.clearHandlers()            ← handlers + confirmHandler クリア
  ├→ engine.resetState()                     ← signer.resetChain() + lastProcessedLog null化 + errorRouter.shutdown()
  └→ Sentinel.instance = null

reset() [テスト用]
  ├→ 環境チェック → 非test/localで警告
  ├→ taskExecutor.clearHandlers()           ← ✅ 呼出済み
  └→ Sentinel.instance = null
```

## 2. 可変状態マップ

| コンポーネント | 可変状態 | 保護 | GC | shutdown時 |
|---------------|---------|------|-----|-----------|
| Sentinel | instance (static) | — | null代入 | null化 |
| IngestionEngine | chainLock | Promise mutex | GC | resetState()でリセット |
| IngestionEngine | lastProcessedLog | — | 上書き | resetState()でnull化 |
| IntegritySigner | previousHash | chainLock内 | GC | resetState()→resetChain()で解放 |
| TaskExecutor | handlers Map | — | clear() | clearHandlers()で解放 |
| TaskExecutor | confirmHandler | — | undefined | clearHandlers()で解放 |
| TaskGenerator | ruleIndex Map | 構築後不変 | GC | 未対応（不要） |
| EventDetector | customRules | 構築後不変 | GC | 未対応（不要） |
| MaskingService | （なし） | static | — | 不要 |
| WhitelistRegistry | validSets, fieldDomains | 構築後不変 | GC | 未対応（不要） |

## 3. 問題と修正方針

### 3.1 shutdown()の完全性 — ✅ 対応済み

`engine.resetState()` により `signer.resetChain()` + `lastProcessedLog` null化 + `errorRouter.shutdown()` を実行。

### 3.2 shutdown()の冪等性 — ✅ 対応済み

`private isShutdown = false` フラグで二重呼出し防止。`if (this.isShutdown) return;` ガード。

### 3.3 config凍結 — ✅ 対応済み

`Sentinel.deepFreeze(config)` でコンストラクタ内でdeep freeze。classインスタンス（Sink等）はfreeze対象外。

### 3.4 ハンドラ蓄積上限 — ✅ 対応済み

`warnIfTooManyHandlers()` で actionType あたり `MAX_HANDLERS_PER_ACTION = 10` 超過時に警告。

### 3.5 onError例外の記録 — ✅ 対応済み

`emitSafe()` + `errorRouter` のダブルフェイル保護で `console.error` フォールバック。
