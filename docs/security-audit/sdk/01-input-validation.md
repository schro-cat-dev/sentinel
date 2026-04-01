# SDK 入力バリデーション・サニタイゼーション監査

## 概要

SDK公開API境界 `Sentinel.ingest()` におけるランタイムバリデーションの完全性を評価する。

---

## チェック項目一覧

### 1. message フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 必須チェック | **OK** | `log-validator.ts:79-81` — `undefined`, `null` を明示的に拒否 |
| 型チェック | **OK** | `log-validator.ts:83-85` — `typeof !== "string"` で拒否 |
| 空文字チェック | **OK** | `log-validator.ts:86-88` — `trim().length === 0` で空白のみも拒否 |
| 最大長チェック | **OK** | `log-validator.ts:89-91` — デフォルト65536バイト |
| null byteチェック | **OK** | `log-validator.ts:92-94` — `\x00` を明示的に拒否 |

### 2. type フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ホワイトリスト検証 | **OK** | `log-validator.ts:98-100` — 7種の許可値のみ通過 |
| undefined許可 | **OK** | 省略時はNormalizerでデフォルト値が設定される |

**許可値**: `BUSINESS-AUDIT`, `SECURITY`, `COMPLIANCE`, `INFRA`, `SYSTEM`, `SLA`, `DEBUG`

### 3. level フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 整数チェック | **OK** | `log-validator.ts:104` — `Number.isInteger()` |
| 範囲チェック | **OK** | `log-validator.ts:104` — `1 <= level <= 6` |
| 浮動小数点拒否 | **OK** | `Number.isInteger()` で `3.5` 等を排除 |

### 4. origin フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ホワイトリスト検証 | **OK** | `log-validator.ts:110-112` — `SYSTEM`, `AI_AGENT` のみ |

### 5. 文字列フィールド群（actorId, traceId, spanId, parentSpanId, boundary, traceInfo）

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 型チェック | **OK** | `log-validator.ts:218-219` |
| 最大長チェック | **OK** | `log-validator.ts:221-223` — デフォルト512 |
| null byteチェック | **OK** | `log-validator.ts:224-226` |
| undefined許可 | **OK** | `log-validator.ts:217` — 省略可 |

### 6. tags 配列

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 配列型チェック | **OK** | `log-validator.ts:129-131` |
| 最大要素数 | **OK** | `log-validator.ts:132-134` — デフォルト100 |
| tag.key 型・長さ | **OK** | `log-validator.ts:137-138` — 最大128 |
| tag.key null byte | **OK** | `log-validator.ts:140-142` |
| tag.category 型・長さ | **OK** | `log-validator.ts:143-145` — 最大1024 |
| tag.category null byte | **OK** | `log-validator.ts:146-148` |

### 7. resourceIds 配列

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 配列型チェック | **OK** | `log-validator.ts:154-156` |
| 最大要素数 | **OK** | `log-validator.ts:157-159` — デフォルト100 |
| 各要素型チェック | **OK** | `log-validator.ts:161-163` |
| 各要素最大長 | **OK** | `log-validator.ts:164-166` — デフォルト512 |
| null byteチェック | **OK** | `log-validator.ts:167-169` |

### 8. details フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 型チェック | **OK** | `log-validator.ts:175-177` |
| 最大長チェック | **OK** | `log-validator.ts:178-180` — デフォルト65536 |
| null byteチェック | **OK** | `log-validator.ts:181-183` |

### 9. input フィールド（JSONValue）

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 概算サイズチェック | **OK** | `log-validator.ts:188-191` — デフォルト1MB |
| 循環参照防御 | **OK** | `log-validator.ts:237` — `WeakSet` で検出 |
| 再帰深度制限 | **OK** | `log-validator.ts:232` — `depth > 20` で停止 |

### 10. ログ全体サイズ

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 総合サイズ上限 | **OK** | `log-validator.ts:210-213` — デフォルト2MB |

### 11. isCritical フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 型チェック | **OK** | `log-validator.ts:115-117` — boolean以外を拒否 |

### 12. aiContext フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| loopDepth 型・範囲 | **OK** | `log-validator.ts:204-206` — 非負整数 |

---

## 防御境界の不足箇所

### 12-a. agentBackLog フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| オブジェクト型チェック | **OK** | `log-validator.ts:196-198` |
| **サイズ制限** | **要改善** | `estimateLogSize()` に含まれるが、個別の `maxAgentBackLogSize` 制限はない |
| **深度制限** | **OK** | 総合サイズチェックで間接的にカバー |

**リスク**: `agentBackLog` に巨大なネストされたオブジェクトを投入するとメモリ消費が増大する可能性がある。ただし `maxTotalLogSize` (2MB) で間接的に制限されるため、実害は限定的。

**推奨パッチ**:
```typescript
// log-validator.ts の agentBackLog 検証セクション
if (input.agentBackLog !== undefined && input.agentBackLog !== null) {
    if (typeof input.agentBackLog !== "object" || Array.isArray(input.agentBackLog)) {
        throw new ValidationError("agentBackLog", "must be an object");
    }
    const backLogSize = estimateJsonSize(input.agentBackLog);
    if (backLogSize > L.maxInputSize) {  // inputと同じ1MB制限を適用
        throw new ValidationError("agentBackLog", `exceeds max size ~${L.maxInputSize} bytes`);
    }
}
```

### 12-b. aiContext の任意フィールド

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| loopDepth以外のフィールド | **要確認** | `aiContext` はオープンな型。任意のキー/値を受け入れる |

**リスク**: `aiContext` に `__proto__` や `constructor` キーを持つオブジェクトが渡された場合、下流のマスキング処理でプロトタイプ汚染が発生する可能性がある。ただし、マスキングサービスは `Object.prototype.hasOwnProperty.call()` を使用しており、`for...in` ループでプロトタイプチェーンのプロパティを拾わない設計。

**判定**: 実害の可能性は **低い** が、防御的に `__proto__` / `constructor` キーの拒否を追加することを推奨。

**推奨パッチ**:
```typescript
if (input.aiContext !== undefined && input.aiContext !== null) {
    const ai = input.aiContext;
    // プロトタイプ汚染防御
    if ('__proto__' in ai || 'constructor' in ai) {
        throw new ValidationError("aiContext", "contains prohibited keys");
    }
    // ...既存の loopDepth 検証
}
```

---

## Go サーバとの整合性

| 項目 | SDK | Go Server | 整合 |
|------|-----|-----------|------|
| MaxFieldLength | 65536 | 65536 | **一致** |
| MaxTagCount | 100 | 100 | **一致** |
| MaxTagKeyLength | 128 | 128 | **一致** |
| MaxTagValueLength | 1024 | 1024 | **一致** |
| MaxResourceIDs | 100 | 100 | **一致** |
| null byte チェック | あり | あり | **一致** |
| UTF-8 検証 | なし（SDK側） | あり | **不一致** |

**UTF-8 検証の不一致について**:
- Go サーバの `sanitizer.go:63-64` は `utf8.ValidString()` で検証
- SDK 側は明示的なUTF-8検証がない
- **リスク**: JavaScript の `String` は内部的にUTF-16。不正なサロゲートペアがそのまま通過する可能性
- **影響**: ローカルモードでは問題なし。remoteモードではgRPCのprotobufが不正UTF-8を拒否するため、トランスポートエラーになる

**推奨パッチ**: SDK側にも明示的なUTF-8検証を追加する場合は以下：
```typescript
function containsLoneSurrogate(s: string): boolean {
    for (let i = 0; i < s.length; i++) {
        const code = s.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
            const next = s.charCodeAt(i + 1);
            if (isNaN(next) || next < 0xDC00 || next > 0xDFFF) return true;
            i++; // skip low surrogate
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
            return true; // lone low surrogate
        }
    }
    return false;
}
```

---

## 総合判定

**評価: A（優秀）**

入力バリデーションは包括的に実装されており、重大な防御漏れはない。SDK/Go Server間の制限値も正確に整合している。改善点は `agentBackLog` の個別サイズ制限と `aiContext` のプロトタイプ汚染防御の2点のみ。いずれも既存の間接的防御（総合サイズ制限、`hasOwnProperty` ガード）でリスクは低い。
