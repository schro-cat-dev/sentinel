# インスタンス管理 詳細監査報告

```yaml
audited_at: "2026-04-01"
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
  ├→ transport.close()                       ← 非冪等の可能性
  ├→ taskExecutor.clearHandlers()            ← handlers + confirmHandler クリア
  ├→ Sentinel.instance = null
  └→ [未実装] signer.resetChain()
      [未実装] config参照の明示的解放

reset() [テスト用]
  ├→ 環境チェック → 非test/localで警告
  └→ Sentinel.instance = null
     [未実装] clearHandlers() 未呼出
```

## 2. 可変状態マップ

| コンポーネント | 可変状態 | 保護 | GC | shutdown時 |
|---------------|---------|------|-----|-----------|
| Sentinel | instance (static) | — | null代入 | null化 |
| IngestionEngine | chainLock | Promise mutex | GC | 未対応 |
| IngestionEngine | lastProcessedLog | — | 上書き | 未対応 |
| IntegritySigner | previousHash | chainLock内 | GC | resetChain()未呼出 |
| TaskExecutor | handlers Map | — | clear() | clearHandlers()で解放 |
| TaskExecutor | confirmHandler | — | undefined | clearHandlers()で解放 |
| TaskGenerator | ruleIndex Map | 構築後不変 | GC | 未対応（不要） |
| EventDetector | customRules | 構築後不変 | GC | 未対応（不要） |
| MaskingService | （なし） | static | — | 不要 |
| WhitelistRegistry | validSets, fieldDomains | 構築後不変 | GC | 未対応（不要） |

## 3. 問題と修正方針

### 3.1 shutdown()の完全性

**現状**: handlers/confirmHandlerクリア、instance null化。signerリセット漏れ。
**修正**: shutdown()にsigner.resetChain()追加。engineへのresetメソッド公開。

### 3.2 shutdown()の冪等性

**現状**: 二重呼出しでtransport.close()が2回実行される。
**修正**: `private shuttingDown = false` フラグで二重呼出し防止。

### 3.3 config凍結

**現状**: configオブジェクトは参照渡し。外部からの変更が内部に影響。
**修正**: initialize()でconfig, taskRules[], detectionRules[], masking.rules[]をdeep freeze。

### 3.4 ハンドラ蓄積上限

**現状**: registerHandler()がpush()のみ。同一actionTypeに無制限追加。
**修正**: actionType当たりの上限（デフォルト10）を設け、超過時に警告。

### 3.5 onError例外の記録

**現状**: `catch { /* */ }` で完全無視。
**修正**: console.errorへのフォールバック出力。
