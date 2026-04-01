# SDK ライフサイクル・リソース管理監査

## 概要

SDK のシングルトンパターン、リソースの取得・解放サイクル、メモリリークリスクを評価する。

---

## チェック項目一覧

### 1. シングルトンライフサイクル

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| シングルトン生成 | **OK** | `index.ts:69-78` — `initialize()` で生成、二重呼び出し時は既存を返却 |
| シングルトン取得 | **OK** | `index.ts:83-88` — 未初期化時は明示的エラー |
| シングルトン解放 | **OK** | `index.ts:115-127` — `shutdown()` で null 化 |
| リセット（テスト用） | **OK** | `index.ts:94-109` — 非テスト環境で警告 |

### 2. shutdown() のリソース解放

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 冪等性 | **OK** | `index.ts:116` — `if (this.isShutdown) return` |
| トランスポート close | **OK** | `index.ts:120` — `await transport?.close?.()` |
| close エラーハンドリング | **OK** | `index.ts:121-123` — `catch {}` でbest-effort |
| ハンドラクリア | **OK** | `index.ts:124` — `taskExecutor.clearHandlers()` |
| エンジン状態リセット | **OK** | `index.ts:125` — `engine.resetState()` |
| シングルトン null 化 | **OK** | `index.ts:126` — `Sentinel.instance = null` |
| **shutdown後のインスタンス参照** | **要注意** | shutdown後も外部がインスタンスへの参照を保持している可能性あり |

**リスク分析**: `shutdown()` 後に外部コードがインスタンスを参照し続けた場合：
- `ingest()` → `Error("Sentinel is shutdown")` がスローされる → **安全**
- `onTaskAction()` → 同上 → **安全**
- `getConfig()` → 設定が返却される → **無害**（設定はfrozen）
- `updateCallbacks()` → `Error("Sentinel is shutdown")` → **安全**

### 3. reset() のリソース解放

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 非テスト環境警告 | **OK** | `index.ts:97-102` — `environment !== "test" && !== "local"` で警告 |
| トランスポート close（best-effort） | **OK** | `index.ts:104` — `try { Promise.resolve(...close?.()).catch(() => {}); } catch { /* */ }` |
| ハンドラクリア | **OK** | `index.ts:105` |
| エンジンリセット | **OK** | `index.ts:106` |
| シングルトン null 化 | **OK** | `index.ts:108` |

**注意点**: `reset()` はトランスポートの `close()` を **fire-and-forget** で呼ぶ（`await` しない）。これは reset がテスト用途であり、高速なリセットが期待されるため。本番環境では `shutdown()` を使用すべき。

### 4. タスクハンドラのメモリリーク

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ハンドラ数の警告 | **OK** | `index.ts:183-192` — 10件超で警告 |
| ハンドラ上限の強制 | **なし** | 警告のみ。登録自体は制限なし |
| unsubscribe 関数の提供 | **OK** | `index.ts:180` — `onTaskAction()` が解除関数を返却 |
| clearHandlers() | **OK** | `shutdown()` と `reset()` で呼び出し |

**リスク分析**:
- ハンドラを大量に登録し続けると、メモリリークが発生する
- 警告は出るが、登録は拒否されない
- **影響**: 長期間運用するサーバプロセスで、ハンドラの登録/解除を適切に行わないとメモリ使用量が増加

**推奨パッチ**:
```typescript
private warnIfTooManyHandlers(actionType: string): void {
    const MAX_HANDLERS_PER_ACTION = 10;
    const HARD_LIMIT = 100;
    const count = this.taskExecutor.getHandlerCount(actionType);
    if (count > HARD_LIMIT) {
        throw new Error(
            `Too many handlers for "${actionType}" (${count}). ` +
            `Maximum ${HARD_LIMIT} handlers per action type. ` +
            `Call the unsubscribe function returned by onTaskAction() to remove unused handlers.`
        );
    }
    if (count > MAX_HANDLERS_PER_ACTION) {
        this.config.logger?.warn(
            `${count} handlers registered for actionType "${actionType}". ` +
            `This may indicate a leak.`,
            { source: "sentinel" },
        );
    }
}
```

### 5. deepFreeze の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 設定の不変性 | **OK** | `index.ts:231-243` — 再帰的 `Object.freeze` |
| クラスインスタンスの除外 | **OK** | `index.ts:237-238` — `ctor !== Object && ctor !== Array` のみfreeze |
| 無限再帰防止 | **OK** | `Object.isFrozen(value)` チェックで既にfrozenなオブジェクトをスキップ |

### 6. IngestionEngine の状態管理

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| async mutex | **OK** | ハッシュチェーン更新時のシリアライゼーション |
| 最終処理ログの保持 | **要注意** | `getLastProcessedLog()` — 前回のログ参照が保持される |
| コールバック例外隔離 | **OK** | `emitSafe()` — コールバック例外が処理パイプラインに影響しない |

**最終処理ログの保持リスク**:
- `dual` モードで使用する `getLastProcessedLog()` は、前回処理したログへの参照を保持
- GCされるまでログデータがメモリに残留
- PII マスキング済みのログであるため、PII漏洩のリスクは低い
- **推奨**: `shutdown()` / `resetState()` で参照をクリアすべき

---

## タイマー・非同期リソース

| リソース | 管理状態 | 根拠 |
|---------|---------|------|
| sendWithTimeout の setTimeout | **OK** | `finally { clearTimeout(timer!) }` |
| タスクハンドラ関数参照 | **OK** | `clearHandlers()` で解放 |
| WeakSet（循環参照検出用） | **OK** | WeakSet は参照先オブジェクトがGCされると自動解放 |
| IntegritySigner の previousHash | **OK** | `resetChain()` で空文字列にリセット |

---

## 総合判定

**評価: B+（良好、軽微な改善余地あり）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| シングルトン管理 | — | **OK** | 生成/取得/解放/リセットすべて適切 |
| shutdown冪等性 | — | **OK** | |
| タイマークリーンアップ | — | **OK** | |
| ハンドラ登録上限なし | LOW | **要改善** | ハードリミット追加推奨 |
| 最終処理ログ保持 | LOW | **要改善** | resetState でクリア推奨 |
| reset() のfire-and-forget close | INFO | **設計上の選択** | テスト用途として妥当 |
