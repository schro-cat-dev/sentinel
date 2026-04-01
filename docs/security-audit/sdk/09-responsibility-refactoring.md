# SDK 責務分離・アーキテクチャ整合性リファクタリング

## 概要

cross-cutting セキュリティ監査の過程で発見された、機能配置・責務分離の問題を整理し、修正方針を定める。

---

## 発見された問題一覧

### HIGH-1: PII パターン二重定義

| 項目 | 詳細 |
|------|------|
| **箇所** | `security/masking-service.ts:11-20`, `shared/utils/error-utils.ts:6-21` |
| **問題** | PIIパターン正規表現が2箇所で独立定義。カバレッジも構文も不一致 |
| **リスク** | パターン更新時の不整合 → 一方でPII漏洩する可能性 |
| **方針** | `security/pii-patterns.ts` に統合。両モジュールからimport |

### HIGH-2: セキュリティロジックが shared 層に混在

| 項目 | 詳細 |
|------|------|
| **箇所** | `shared/utils/error-utils.ts` — `isPiiSafe()`, `maskPiiContext()` |
| **問題** | PII検出・マスキングはsecurity層の責務。shared層に配置すると監査時に見落とされる |
| **リスク** | セキュリティ監査の網羅性低下、レイヤー依存関係の混乱 |
| **方針** | `security/pii-context-masker.ts` に移動。`error-utils.ts` からは再export（後方互換） |

### MEDIUM-3: ハンドラ制限が Sentinel クラスに実装

| 項目 | 詳細 |
|------|------|
| **箇所** | `index.ts:183-213` — `HARD_HANDLER_LIMIT`, `enforceHandlerLimit()`, `warnIfTooManyHandlers()` |
| **問題** | ハンドラの登録・管理は `TaskExecutor` の責務。Sentinel は委譲のみであるべき |
| **リスク** | Sentinel クラスの肥大化、テスト困難性 |
| **方針** | `TaskExecutor.registerHandler()` に制限ロジックを移動 |

### MEDIUM-4: ErrorRouter が注入ではなく内部生成

| 項目 | 詳細 |
|------|------|
| **箇所** | `core/engine/ingestion-engine.ts:52-54` |
| **問題** | IngestionEngine が `new ErrorRouter(config)` で直接生成。DI原則違反 |
| **リスク** | テスタビリティ低下、error-routingモジュールとの密結合 |
| **方針** | コンストラクタ引数にオプショナルな `ErrorRouter` を追加。Sentinel.initialize で生成して渡す |

### MEDIUM-5: PII カテゴリ定義の重複

| 項目 | 詳細 |
|------|------|
| **箇所** | `configs/masking-rule.ts` (型定義), `configs/config-loader.ts:231-234` (Set), `validation/whitelists/privacy-whitelist.ts` (配列) |
| **問題** | 同じPIIカテゴリが3箇所で独立定義。追加・変更時に不整合リスク |
| **方針** | `configs/masking-rule.ts` で `PII_CATEGORIES` 定数を定義。他はimport |

### LOW-6: sentinel-config.ts の dynamic import type

| 項目 | 詳細 |
|------|------|
| **箇所** | `configs/sentinel-config.ts:85,88` |
| **問題** | `import("../error-routing/types").ErrorRoutingConfig` の動的型import。IDE補完が効かない |
| **方針** | 通常の `import type` に変更 |

---

## 修正順序

依存関係を考慮した修正順序:

1. **PII カテゴリ定義統合** (MEDIUM-5) — 他の修正の前提
2. **PII パターン統合** (HIGH-1) — security/pii-patterns.ts 新設
3. **maskPiiContext 移動** (HIGH-2) — pii-patterns.ts を使用
4. **ハンドラ制限移動** (MEDIUM-3) — 独立した変更
5. **ErrorRouter DI化** (MEDIUM-4) — 独立した変更
6. **dynamic import type 修正** (LOW-6) — 軽微な修正

---

## 修正方針の原則

- **後方互換**: 公開APIの変更はなし。内部リファクタリングのみ
- **TDD**: テストを先に書き、RED → 実装 → GREEN の順
- **段階的**: 各修正は独立してテスト可能。途中でも全テストがGREEN
- **re-export**: 移動元からの再exportで、外部からの参照パスを維持

---

## 修正ステータス（2026-04-02 完了）

| ID | 問題 | ステータス | 修正内容 |
|----|------|-----------|---------|
| HIGH-1 | PII パターン二重定義 | **✅ 完了** | `security/pii-patterns.ts` 新設。`masking-service.ts` と `error-utils.ts` からimport |
| HIGH-2 | セキュリティロジック mixed | **✅ 完了** | `security/pii-context-masker.ts` に `isPiiSafe`/`maskPiiContext` を移動。`error-utils.ts` から再export |
| MEDIUM-3 | ハンドラ制限 in Sentinel | **✅ 完了** | `TaskExecutor.registerHandler()` にハードリミット(100)を統合。Sentinel から制限ロジック削除 |
| MEDIUM-4 | ErrorRouter 内部生成 | **✅ 完了** | `IngestionEngine` コンストラクタにオプショナル `errorRouter` 引数追加。`Sentinel.initialize` で生成して注入 |
| MEDIUM-5 | PII カテゴリ重複 | **✅ 完了** | `configs/masking-rule.ts` に `PII_CATEGORIES` 定数を定義。`config-loader.ts`, `privacy-whitelist.ts` からimport |
| LOW-6 | dynamic import type | **✅ 完了** | `sentinel-config.ts` の動的importを通常の `import type` に変更 |

**新規ファイル**:
- `src/security/pii-patterns.ts` — PIIパターンの単一ソース定義
- `src/security/pii-context-masker.ts` — PII検出・マスキング（error-utils.ts から移動）

**全テスト**: 67ファイル / 2455テスト / 0失敗
