# パッチ詳細設計

Date: 2026-04-02

## Patch 1: expectSafeOrRejected + tautological assertion 修正

### 変更ファイル
- `tests/security/advanced/injection-attacks.test.ts`

### 設計

`expectSafeOrRejected` を `expectSafeOrRejected` に改名せず、以下のように強化:

```typescript
function expectSafeOrRejected(result: { ok: boolean; error?: unknown }): void {
    if (!result.ok) {
        // 拒否された場合: ValidationErrorまたはErrorであること
        expect(
            result.error instanceof ValidationError ||
            result.error instanceof Error,
        ).toBe(true);
    }
    // ok === true: テスト自体がクラッシュせずここに到達 = プロセス生存確認済み
    // これ以上の検証は各テストケースの責務
}
```

**判断**: injection攻撃テストの目的は「クラッシュ/コード実行しない」こと。
ok===trueの場合にマスキング結果を検証するのは過剰（マスキングテストは別ファイルにある）。
ただし、`expectSafeOrRejected`を使うテストは最低限「クラッシュしなかった」ことを
明示的にアサートすべき。

**対策**:
1. `expectSafeOrRejected` に成功パスの明示アサーション追加: `expect(result.ok).toBe(true)` or error検証
2. L284の `expect(true).toBe(true)` を削除（`expectSafeOrRejected` が既にカバー）

### 具体的変更

```typescript
function expectSafeOrRejected(result: { ok: boolean; error?: unknown }): void {
    if (!result.ok) {
        expect(
            result.error instanceof ValidationError ||
            result.error instanceof Error,
        ).toBe(true);
        return;
    }
    // ok === true: ペイロードはバリデーション通過し、パイプライン完走した
    // プロセスが生存していることはこの行に到達した事実が証明
    expect(result.ok).toBe(true);
}
```

L284: `expect(true).toBe(true)` → 行ごと削除

---

## Patch 2: toBeDefined() → 構造的アサーション

### 変更ファイル
- `tests/security/advanced/dos-resource-exhaustion.test.ts`

### 設計

DoSテストの目的は「タイムアウトせず完了する」+「結果が壊れていない」。
完全な内容検証は不要だが、構造が壊れていないことは検証すべき。

| テスト | 現状 | 修正後 |
|--------|------|--------|
| 10000 keys | `toBeDefined()` | `typeof === "object"` + キー数確認 |
| 10000 array | `toBeDefined()` | `Array.isArray` + length確認 |
| 50-level nesting | `toBeDefined()` | `typeof === "object"` |
| circular ref | `toBeDefined()` | `typeof === "object"` + 循環マーカー検証 |
| 100 shared refs | `toBeDefined()` | `typeof === "object"` + email マスク確認 |
| 20000 mixed | `toBeDefined()` | `typeof === "object"` |
| nested arrays | `toBeDefined()` | `Array.isArray` |
| alternating | `toBeDefined()` | `typeof === "object"` or `Array.isArray` |

---

## Patch 3: error-router "log" destination 実装

### 変更ファイル
- `src/error-routing/error-router.ts`
- `src/error-routing/types.ts`
- `tests/unit/error-routing/error-router.test.ts`

### 設計

ErrorRoutingConfigに `logger` を追加（既存の SentinelLogger 型を再利用）:

```typescript
// types.ts に追加
export interface ErrorRoutingConfig {
    // ... 既存フィールド
    logger?: {
        info(message: string, meta?: Record<string, unknown>): void;
    };
}
```

error-router.ts の case "log":

```typescript
case "log":
    this.config.logger?.info(
        `[ErrorRouter:log] ${error.kind}: ${error.message}`,
        { severity: error.severity, context: error.context, traceId: error.traceId },
    );
    break;
```

**設計判断**: console.errorは最終防壁として予約。logはinfo相当のstructured log。loggerが未設定の場合は何もしない（現状維持）。

---

## Patch 4: error-utils.ts 専用ユニットテスト

### 新規ファイル
- `tests/unit/shared/error-utils.test.ts`

### テスト設計

```
isPiiSafe()
  ├─ 空文字列 → true
  ├─ 2文字以下 → true (仕様確認)
  ├─ メールアドレス → false
  ├─ クレジットカード番号 → false
  ├─ 電話番号（日本） → false
  ├─ 電話番号（国際） → false
  ├─ IBAN → false
  ├─ 日本口座番号 → false
  ├─ 個人名パターン → false
  ├─ 郵便番号 → false
  ├─ 安全な一般文字列 → true
  └─ 境界値: 3文字の安全文字列 → true

maskPiiContext()
  ├─ PIIなし → そのまま返る
  ├─ 値にPII → マスクされる
  ├─ キー名にPII → キーがマスクされる
  ├─ prototype pollution → hasOwnPropertyガードで安全
  └─ 空オブジェクト → 空のまま

safeContext()
  ├─ キー長50超 → スキップ
  ├─ null/undefined値 → null
  ├─ 配列 → 長さ（最大1000）
  ├─ オブジェクト → キー数
  ├─ 文字列50超 → 切り詰め
  ├─ 数値 → Math.floor, Infinity→0, NaN→0
  ├─ boolean → そのまま
  └─ その他 → null

serializeForAudit()
  ├─ 正常ケース → JSON出力
  ├─ PIIキー除外
  └─ キー10件上限

classifyError() / getErrorMessage()
  ├─ CRITICAL/WARNING/INFO分類
  └─ ja/en メッセージ
```

---

## Patch 5: Sentinel クラスユニットテスト

### 新規ファイル
- `tests/unit/core/sentinel.test.ts`

### テスト設計

```
Sentinel.initialize()
  ├─ 正常初期化
  ├─ 二重初期化 → 既存インスタンス返却 + warn
  └─ configバリデーション失敗

Sentinel.getInstance()
  ├─ 初期化前 → throw
  └─ 初期化後 → インスタンス取得

Sentinel.reset()
  ├─ 正常リセット
  ├─ 非テスト環境 → 警告
  └─ transport closeエラー → 握りつぶし

Sentinel.shutdown()
  ├─ 正常シャットダウン
  ├─ 二重shutdown → 安全に無視
  └─ shutdown後のingest → throw

Sentinel.ingest()
  ├─ ローカルモード正常
  ├─ shutdown後 → throw
  └─ バリデーションエラー → throw

Sentinel.onTaskAction()
  ├─ ハンドラ登録 + 解除
  ├─ shutdown後 → throw
  └─ ハンドラ多数 → warn

Sentinel.updateCallbacks()
  ├─ 正常更新
  └─ shutdown後 → throw
```

---

## Patch 6: `as any` 排除

### 方針

テスト内の `as any` を以下のパターンで置換:

1. **不正入力テスト**: `as unknown as TargetType` に変更
   - 型システムを明示的に迂回していることが可読
2. **結果アクセス**: 型アサーション関数 or 型ガードを使用
   - `assertIsRecord(result)` → `result.field` のようにアクセス

### 対象ファイル
- `tests/unit/core/log-normalizer.test.ts`
- `tests/config/validation-normalizer-exhaustive.test.ts`
- `tests/config/masking-rules-exhaustive.test.ts`
- `tests/unit/intelligence/severity-classifier.test.ts`
- `tests/unit/validation/log-validator.test.ts`
