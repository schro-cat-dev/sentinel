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

## 防御境界の不足箇所と対策ステータス

### 12-a. agentBackLog フィールド — ✅ 修正済み (GAP-02)

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| オブジェクト型チェック | **OK** | `log-validator.ts:198-200` |
| **エントリ数制限** | **OK（修正済み）** | `log-validator.ts:203-205` — 最大100エントリ |
| **サイズ制限** | **OK（修正済み）** | `log-validator.ts:206-208` — `maxInputSize`(1MB) と同じ制限を適用 |
| **深度制限** | **OK** | 総合サイズチェックで間接的にカバー |

**修正内容**: エントリ数上限(100)と個別サイズ制限(`maxInputSize`)を追加。テスト: `tests/security/sdk-audit-fixes.test.ts`

### 12-b. aiContext の任意フィールド — ✅ 修正済み (SDK-B)

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| loopDepth以外のフィールド | **OK（修正済み）** | `__proto__` / `constructor` キーを拒否 |

**修正内容**: `aiContext` に対する `__proto__` / `constructor` キーの明示的拒否を追加。テスト: `tests/security/sdk-audit-fixes.test.ts`

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
| UTF-8 検証 | **あり（修正済み）** | あり | **一致** |

**UTF-8 検証 — ✅ 修正済み (VULN-013)**:
- Go サーバの `sanitizer.go:63-64` は `utf8.ValidString()` で検証
- SDK 側に `containsLoneSurrogate()` を追加。孤立サロゲート（\uD800-\uDBFF の後に \uDC00-\uDFFF が続かない、または孤立 \uDC00-\uDFFF）を検出・拒否
- テスト: `tests/security/sdk-audit-fixes.test.ts` — message, details, actorId, tags 等の全文字列フィールドで検証

---

## 総合判定

**評価: A+（優秀 — 全指摘事項修正済み）**

入力バリデーションは包括的に実装されており、重大な防御漏れはない。SDK/Go Server間の制限値も正確に整合している。

**修正済み項目（2026-04-02）**:
- GAP-02: `agentBackLog` のエントリ数制限(100)と個別サイズ制限(`maxInputSize`)を追加
- SDK-B: `aiContext` の `__proto__` / `constructor` キー拒否を追加
- VULN-013: UTF-8 孤立サロゲート検証を全文字列フィールドに追加（Go Server と整合）
