# クライアントSDK (TypeScript) — セキュリティ所見

**スコープ:** `src/`, `examples/`, `samples/`, `types/`
**最終監査:** 2026-03-30

---

## C-001: CREDIT_CARD ReDoS (CRITICAL)

**ファイル:** `src/security/masking-service.ts:11`
**CWE:** CWE-1333 (Inefficient Regular Expression Complexity)

### 問題
```typescript
CREDIT_CARD: /\b(?:\d[ -]*?){13,19}\b/g
```
ネストされた量指定子 `(?:\d[ -]*?){13,19}` は、マッチ失敗時に指数的バックトラッキングを引き起こす。
攻撃ペイロード例: `"1111 1111 1111 1111 1111 11111111888888"`

### 影響
- CPU使用率100%到達、プロセスハング
- ログ処理パイプライン全体のDoS
- 攻撃者はログメッセージに悪意ある文字列を注入するだけで発動可能

### 対策
```typescript
// 固定構造パターンに変更（バックトラッキングなし）
CREDIT_CARD: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g,
```

### 検証方法
```typescript
const start = performance.now();
const malicious = "1111 1111 1111 1111 1111 11111111888888";
malicious.match(/\b(?:\d[ -]*?){13,19}\b/g);
const elapsed = performance.now() - start;
// 修正前: 数秒〜数十秒  修正後: < 1ms
```

---

## C-002: 動的RegExp未検証 (HIGH)

**ファイル:** `src/security/masking-service.ts:148-150, 163-165`
**CWE:** CWE-1333, CWE-20

### 問題
```typescript
const globalPattern = new RegExp(rule.pattern.source, "g");
```
ユーザーが `SentinelConfig.masking.rules` で提供するカスタム正規表現パターンが、
ReDoS安全性の検証なしに `new RegExp()` へ渡される。

### 影響
- ユーザー設定経由でReDoS攻撃が可能
- SDK利用者が意図せず脆弱なパターンを設定するリスク

### 対策
```typescript
import { isSafe } from 'safe-regex2'; // または自前の検証

function validateRegex(pattern: RegExp): void {
  if (!isSafe(pattern.source)) {
    throw new Error(`Unsafe regex pattern: potential ReDoS`);
  }
}
```

> **注:** ランタイム依存ゼロ方針を維持する場合、簡易的なネスト量指定子検出を自前実装する。

---

## C-003: Errorオブジェクト情報漏洩 (HIGH)

**ファイル:** `src/security/masking-service.ts:180-182`
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

### 問題
```typescript
console.warn(`Masking rule failed: ${String(rule.type)}`, error);
```
`error` オブジェクトがそのまま `console.warn` に渡され、スタックトレース・ファイルパス・内部状態が漏洩する。

### 影響
- 内部ファイルパスの露出（攻撃者への情報提供）
- ログ集約サービス経由で機密情報が保存される

### 対策
```typescript
console.warn(`Masking rule failed: ${String(rule.type)}`);
// エラー詳細はデバッグレベルのみ
if (process.env.NODE_ENV === 'development') {
  console.debug('Masking error detail:', error instanceof Error ? error.message : 'unknown');
}
```

---

## C-004: Prototype Pollution (MEDIUM)

**ファイル:** `src/core/task/task-generator.ts:86-87`
**CWE:** CWE-1321

### 問題
```typescript
executionParams: { ...rule.executionParams },
guardrails: { ...rule.guardrails },
```
`rule` がJSONデシリアライズ由来の場合、`__proto__` や `constructor` プロパティがスプレッドで伝播する。

### 対策
```typescript
function safeCopy<T extends Record<string, unknown>>(obj: T): T {
  return Object.fromEntries(
    Object.entries(obj).filter(([k]) => k !== '__proto__' && k !== 'constructor')
  ) as T;
}
```

---

## C-005: タスク実行パラメータ未検証 (MEDIUM)

**ファイル:** `src/types/task.ts:41-46`
**CWE:** CWE-20

### 問題
`targetEndpoint`, `scriptIdentifier`, `promptTemplate` が検証なしでハンドラに渡される。

### 対策
SDK境界 (`index.ts` の `ingest()`) で以下を検証:
- `targetEndpoint`: URL形式 + プロトコル制限 (https only)
- `scriptIdentifier`: 英数字+ハイフンのみ
- `promptTemplate`: テンプレートインジェクション対策（`{{}}` のみ許可）

---

## C-006: PII正規表現の過剰マッチ (MEDIUM)

**ファイル:** `src/security/masking-service.ts:18`, `src/shared/utils/error-utils.ts:6-21`
**CWE:** CWE-200

### 問題
```typescript
HEALTH_INSURANCE: /[A-Z0-9]{8,10}/g
```
この正規表現はあらゆる8〜10文字の英数字列にマッチし、正当なデータを過剰にマスクする。

### 対策
日本の保険証番号形式に限定するか、コンテキスト付きパターンに変更:
```typescript
HEALTH_INSURANCE: /\b\d{2}[\s-]?\d{2}[\s-]?\d{6}\b/g
```

---

## C-007: trim/length不整合 (LOW)

**ファイル:** `src/core/engine/log-normalizer.ts:44-48`

### 問題
空白チェックは `trim()` 後、長さチェックは `trim()` 前。空白のみの長大文字列が通過する。

---

## C-008: ハンドラ実行の順序依存 (LOW)

**ファイル:** `src/core/task/task-executor.ts:89-91`

### 問題
最初のハンドラが失敗すると後続ハンドラが実行されない。

---

## C-009: ESLintセキュリティプラグイン欠如 (LOW)

**ファイル:** `eslint.config.js`

### 推奨
```bash
npm install -D eslint-plugin-security
```

---

## C-010: ハッシュチェーン初期値未文書化 (INFO)

**ファイル:** `src/security/integrity-signer.ts:14`

初期ハッシュが空文字列 `""` であることが文書化されていない。
Genesis blockとして明示的な定数を使うことを推奨。

---

## C-011: gRPC insecure (example内) (INFO)

**ファイル:** `examples/grpc-transport.ts:63`

サンプルコード内で `grpc.credentials.createInsecure()` を使用。
`// WARNING: Development only` コメントを付与すべき。
