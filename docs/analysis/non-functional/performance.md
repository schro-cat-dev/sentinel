# パフォーマンス解析

```yaml
analyzed_at: "2026-04-01"
based_on: "0ed9ab5"
status: current
last_updated: "2026-04-02"
```

## 所見一覧

### P-1: RegExp毎回再コンパイル [HIGH]

**箇所:** `src/security/masking-service.ts:151-154, 166-169`

`maskString()` は各文字列フィールドの処理ごとに `new RegExp(pattern.source, "g")` を呼ぶ。ネストされたLogオブジェクト（50個の文字列フィールド x 8ルール = 400回のRegExp生成）ではオーバーヘッドが顕著。

**根本原因:** `/g` フラグ付きRegExpの `lastIndex` ステートフル性を回避するため毎回新規生成している。

**改善案:** PII_PATTERNSの `lastIndex` を呼出前にリセットするか、mask呼出単位でRegExpキャッシュを生成する。
```typescript
const freshPattern = new RegExp(piiPattern.source, piiPattern.flags);
// → piiPattern.lastIndex = 0; で十分
```

### P-2: maskInternal の再帰でcontextオブジェクトを毎回コピー [MEDIUM]

**箇所:** `src/security/masking-service.ts:77, 125`

`{ ...context, depth: context.depth }` は再帰のたびにオブジェクトを生成するが、`seen` WeakSetは参照共有で `depth` は try/finally で管理済み。コピーは不要。

### P-3: preserveFields が Array — O(n) ルックアップ [MEDIUM]

**箇所:** `src/security/masking-service.ts:100`

`preserveFields.includes(key)` はO(n)。`Set<string>` に変換すればO(1)。mask()の先頭で `new Set(preserveFields)` を作るだけで改善。

### P-4: isJsonValue + deterministicStringify で二重走査 [LOW]

**箇所:** `src/security/integrity-signer.ts:65, 69-91`

`isJsonValue()` でオブジェクト全体を検証した後、`deterministicStringify()` で再度全体を走査。1パスに統合可能。

### P-5: 同期crypto（createHash）が async mutex 内 [INFO]

**箇所:** `src/security/integrity-signer.ts:44-46`

SHA-256計算自体は高速だが、async mutexでシリアライズされた区間内にあるため、高スループット時にはレイテンシに寄与。
