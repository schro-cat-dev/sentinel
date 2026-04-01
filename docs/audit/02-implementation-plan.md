# 実装計画

Date: 2026-04-02

## 実装順序

依存関係を考慮し、以下の順序で実装する。全てTDD。

### Phase 1: 実装の穴を埋める（テストファースト）

| Step | 対象 | TDD順序 |
|------|------|---------|
| 1-1 | error-router "log" | RED: logが呼ばれることをテスト → GREEN: 実装 |
| 1-2 | error-utils 専用テスト | RED: 全関数のテスト作成 → GREEN: 既存実装で通る（通らないケースがあれば修正） |
| 1-3 | Sentinel ユニットテスト | RED: ライフサイクルテスト → GREEN: 既存実装で通る |

### Phase 2: テストの誤魔化しを修正

| Step | 対象 |
|------|------|
| 2-1 | injection-attacks.test.ts: expectSafeOrRejected強化 + tautology削除 |
| 2-2 | dos-resource-exhaustion.test.ts: toBeDefined → 構造検証 |

### Phase 3: 型安全性

| Step | 対象 |
|------|------|
| 3-1 | 全テストファイルの `as any` → `as unknown as Type` に置換 |

## 無限ループ防止策

- error-router: maxRoutingDepth=1 の既存制約を維持
- テスト実行: `vitest run` を使用（watchモード禁止）
- TDDサイクル: RED→GREEN→REFACTOR を1パッチ単位で完了してから次へ

## 型安全ポリシー

- 新規コード: `any` 禁止。`unknown` + 型ガード or `as unknown as T` のみ
- テスト: 不正入力には `as unknown as T` を使用
- 結果アクセス: `Record<string, unknown>` + 型ガード
