# Sentinel テスト・実装 品質監査レポート

Date: 2026-04-02

## 1. テストの誤魔化し（Fake Tests）

### 1.1 [CRITICAL] expectSafeOrRejected() — 成功パスでアサーションゼロ

**場所**: `tests/security/advanced/injection-attacks.test.ts:58-67`

```typescript
function expectSafeOrRejected(result: { ok: boolean; error?: unknown }): void {
    if (!result.ok) {
        expect(result.error instanceof ValidationError || result.error instanceof Error).toBe(true);
    }
    // ok === true → 何も検証しない
}
```

**影響範囲**: injection攻撃テスト100件以上がこのヘルパー経由。`result.ok === true` の場合、ペイロードが本当に安全に処理されたか（マスキングされたか、エスケープされたか）を一切検証していない。

**リスク**: インジェクションペイロードがそのまま通過してもテストはパスする。

### 1.2 [CRITICAL] expect(true).toBe(true) — トートロジー

**場所**: `tests/security/advanced/injection-attacks.test.ts:284`

プロセスが生存していることをテストしたいのだが、テストフレームワークがこの行を実行した時点でプロセスは生存しているので、このアサーションは常にパスする。

### 1.3 [HIGH] toBeDefined()だけのセキュリティテスト — 15件以上

**場所**: `tests/security/advanced/dos-resource-exhaustion.test.ts`

10,000キーのオブジェクトをマスキングした結果が「存在する」ことだけ確認。マスキングが実際に動いたか、結果のデータ構造が正しいかは検証なし。

**対象箇所**:
- L48: 10,000 keys → `toBeDefined()`
- L56: 10,000 element array → `toBeDefined()`
- L78: 50-level nesting → `toBeDefined()`
- L108: circular reference → `toBeDefined()`
- L120: 100 shared refs → `toBeDefined()`
- L144: 20,000 mixed keys → `toBeDefined()`
- L155: nested arrays → `toBeDefined()`
- L170: alternating nesting → `toBeDefined()`

## 2. 実装の誤魔化し（Incomplete Implementation）

### 2.1 [HIGH] case "log" が何もしない

**場所**: `src/error-routing/error-router.ts:63-65`

```typescript
case "log":
    break;  // 実際のログ出力なし
```

ルーティングエンジンが `"log"` destinationを返しても何も起きない。

### 2.2 [MEDIUM] 短い文字列がPIIチェックをバイパス

**場所**: `src/shared/utils/error-utils.ts:25`

```typescript
if (!value || value.length < 3) return true;  // 2文字以下は無条件で安全扱い
```

意図的な最適化の可能性はあるが、金融コード等が2文字のケースに対するドキュメントがない。

### 2.3 [LOW] サイレントcatch — 3箇所

**場所**: `src/index.ts:104, 121-123, 164`

best-effort設計として妥当だが、デバッグ時に問題特定が困難になる。

## 3. テストカバレッジのギャップ

### 3.1 [CRITICAL] src/index.ts — Sentinel本体のユニットテストなし

メインAPI (`initialize`, `getInstance`, `reset`, `shutdown`, `ingest`, `onTaskAction`, `updateCallbacks`) に対する専用ユニットテストファイルが存在しない。

### 3.2 [HIGH] src/shared/utils/error-utils.ts — 専用テストなし

`isPiiSafe()`, `maskPiiContext()`, `safeContext()`, `serializeForAudit()`, `classifyError()`, `getErrorMessage()` が間接テストのみ。PII正規表現の境界値テストが完全に欠落。

## 4. 型安全性の問題

### 4.1 テスト内 `as any` の乱用（20箇所以上）

不正入力テスト用だが、`as unknown` + 型ガードに置き換えるべき。主な箇所:
- `tests/unit/core/log-normalizer.test.ts`
- `tests/config/validation-normalizer-exhaustive.test.ts`
- `tests/config/masking-rules-exhaustive.test.ts`
- `tests/unit/intelligence/severity-classifier.test.ts`
- `tests/unit/validation/log-validator.test.ts`
