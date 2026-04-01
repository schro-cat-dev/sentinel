# SDK PII マスキング防御分析

## 概要

`MaskingService` はログ内の個人情報 (PII) を再帰的にマスキングする。8種の組込みPIIパターン、REGEX ルール、KEY_MATCH ルールの3方式をサポート。

---

## チェック項目一覧

### 1. 再帰制御

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 最大深度制限 | **OK** | `masking-service.ts:51` — `maxDepth ?? 10`。深度超過時は `"[CIRCULAR_REFERENCE_OR_TOO_DEEP]"` 返却 |
| 循環参照検出 | **OK** | `masking-service.ts:70` — `WeakSet` で検出。循環参照ログは `"[CIRCULAR_REFERENCE_OR_TOO_DEEP]"` |
| 配列長制限 | **OK** | `masking-service.ts:79` — `maxArrayLength ?? 50`。超過分はサイレントにスキップ |
| 深度カウンタの巻き戻し | **OK** | `masking-service.ts:151-153` — `finally` ブロックで `context.depth--` |

**攻撃シナリオ**: 深くネストされたオブジェクト（depth > 10）を持つログを投入。

**結果**: 安全。深度10で `"[CIRCULAR_REFERENCE_OR_TOO_DEEP]"` に置換され、スタックオーバーフローは発生しない。

### 2. PII パターンの状態管理

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| `lastIndex` リセット | **OK** | `masking-service.ts:185` — `piiPattern.lastIndex = 0` で毎回リセット |
| global フラグの一貫性 | **OK** | 組込みパターンは全て `/g` フラグ付き。`replace()` で全出現をマスク |
| ユーザREGEXのフラグ正規化 | **OK** | `masking-service.ts:169` — `flags.replace(/[gy]/g, "")` で `y` `g` を除去後 `g` を追加 |

### 3. KEY_MATCH ルール

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 大文字小文字非依存 | **OK** | `masking-service.ts:121-126` — `key.toLowerCase()` と `sk.toLowerCase()` で比較 |
| プレースホルダ | **OK** | `masking-service.ts:131` — `keyMatchRule.replacement ?? "[MASKED_KEY]"` |
| preserveFields 優先 | **OK** | `masking-service.ts:116-119` — preserve判定が KEY_MATCH より先 |

### 4. hasOwnProperty ガード

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| プロトタイプチェーン遮断 | **OK** | `masking-service.ts:108` — `Object.prototype.hasOwnProperty.call(obj, key)` |

**攻撃シナリオ**: `{ __proto__: { isAdmin: true } }` を含むログを投入。

**結果**: 安全。`hasOwnProperty` ガードにより `__proto__` のプロパティは列挙されない。

### 5. エラーハンドリング

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| マスキングルール失敗時の継続 | **OK** | `masking-service.ts:198-201` — `catch` で警告ログを出力し `continue` |
| ロガー未設定時の安全性 | **OK** | `logger?.warn(...)` — optional chaining でnull安全 |

### 6. マスキングバイパスリスク

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| preserveFields による除外 | **設計上** | ユーザが指定したフィールドはマスキングされない。デフォルトは `traceId`, `spanId` のみ |
| number/boolean の非マスキング | **OK** | `masking-service.ts:45-46` — 文字列以外はそのまま返却。PIIが数値フィールドに格納されるケースは想定外 |
| 配列超過分の非マスキング | **要注意** | `maxArrayLength` (50) を超える要素はスキップされ、マスキングされない |

**配列超過のリスク**:
- `maxArrayLength` 超過分の要素が出力に含まれない（配列が切り詰められる）
- PII を含む要素が51番目以降にある場合、マスキングされないまま出力に含まれると問題
- 実装を再確認: `masking-service.ts:80-101` — `for` ループが `maxLength` で終了し、残りの要素は `result` 配列に含まれない → **安全**（切り詰められる=出力されない）

### 7. マスキング順序の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ルール適用順序 | **OK** | `masking-service.ts:164` — 定義順に適用。先のルールが後のルールの入力を変更する設計 |
| 二重マスキング防止 | **部分的** | すでにマスキング済みの `[MASKED_EMAIL]` 等が別ルールで再マスキングされる可能性は低いが、カスタムREGEXが広範すぎるとマスキング文字列自体を変更する可能性あり |

---

## Go サーバとの比較

| 項目 | SDK | Go Server |
|------|-----|-----------|
| maxDepth | 10 | 32 |
| 循環参照検出 | WeakSet | JSON marshal/unmarshalで暗黙的に検出 |
| PII パターン種類 | 8種 | 4種 (EMAIL, CREDIT_CARD, PHONE, GOVERNMENT_ID) |
| ポリシーベースマスキング | なし | あり（LogType, Origin, Level条件付き） |
| preserveFields | 設定で指定 | 設定で指定 |

**差異の影響**:
- SDK が8種のPIIパターンを持つのに対し、Goサーバは4種。`dual` モードではSDK側で先にマスキングされるため問題なし
- SDK に `maxDepth=10` はGoサーバの32より厳格。SDK側で深いオブジェクトが切り詰められる可能性があるが、セキュリティ上は SDK 側が厳格なほうが望ましい

---

## 総合判定

**評価: A（優秀）**

PIIマスキングは堅牢に実装されている。循環参照防御、深度制限、配列長制限、`hasOwnProperty` ガード、エラー時の継続処理が適切に設計されている。改善点は以下のみ：

1. **配列超過時のログ**: `maxArrayLength` 超過時に警告ログを出すと、運用上有用
2. **GoサーバとのPIIパターン差異**: ドキュメントに明記すべき
