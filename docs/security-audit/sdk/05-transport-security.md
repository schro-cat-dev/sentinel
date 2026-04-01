# SDK トランスポート・通信セキュリティ監査

## 概要

SDK は `TransportConfig` により3つのモード（`local`, `remote`, `dual`）をサポート。トランスポート実装はユーザが注入する設計（zero-dependency原則）。

---

## チェック項目一覧

### 1. タイムアウト制御

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| デフォルトタイムアウト | **OK** | `index.ts:250` — `timeoutMs ?? 30_000`（30秒） |
| タイムアウト実装 | **OK** | `index.ts:256-259` — `Promise.race([sendPromise, timeoutPromise])` |
| タイマークリーンアップ | **OK** | `index.ts:261` — `finally { clearTimeout(timer!) }` |

### 2. fallbackToLocal の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| remote 失敗時のフォールバック | **OK** | `index.ts:148-151` — `fallbackToLocal` が `true` の場合のみローカル処理にフォールバック |
| エラーサイレンシング | **要注意** | フォールバック時にリモートエラーがロストする |

**リスク分析**:

```typescript
// index.ts:143-152
if (mode === "remote" && this.transportConfig.transport) {
    try {
        const normalized = this.engine.normalizeOnly(log);
        return await this.sendWithTimeout(normalized);
    } catch (err) {
        if (this.transportConfig.fallbackToLocal) {
            return this.engine.handle(log);  // ← リモートエラーがロスト
        }
        throw err;
    }
}
```

- `fallbackToLocal=true` の場合、リモート送信失敗のエラーは完全に飲み込まれる
- ユーザはフォールバックが発生したことを知る手段がない（`IngestionResult` にフォールバック情報がない）
- **推奨**: `IngestionResult` に `fallbackUsed: boolean` と `transportError` フィールドを追加（`dual` モードでは既に `transportError` が存在）

**推奨パッチ**:
```typescript
if (this.transportConfig.fallbackToLocal) {
    const result = await this.engine.handle(log);
    result.transportError = err instanceof Error ? err.message : String(err);
    try { this.engine.getOnError()?.(err instanceof Error ? err : new Error(String(err)), "transport.fallback"); } catch { /* */ }
    return result;
}
```

### 3. dual モードのエラー伝播

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ローカル処理の独立性 | **OK** | `index.ts:155-168` — ローカル処理結果は必ず返却 |
| リモートエラーの記録 | **OK** | `index.ts:163` — `localResult.transportError = error.message` |
| onError コールバック呼び出し | **OK** | `index.ts:164` — `try { this.engine.getOnError()?.(error, "transport.dual"); } catch { /* */ }` |

### 4. トランスポートインターフェースのセキュリティ契約

```typescript
interface RemoteTransport {
    send(log: Log): Promise<IngestionResult>;
    healthCheck?(): Promise<boolean>;
    close?(): Promise<void>;
}
```

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| TLS 強制 | **なし** | SDK はトランスポートの暗号化を強制しない。ユーザ実装に委任 |
| 認証ヘッダ強制 | **なし** | SDK はAPI keyなどの認証情報をトランスポートに注入しない |
| URL バリデーション | **なし** | SDK はトランスポート先URLを検証しない |
| 応答サイズ制限 | **なし** | `IngestionResult` のサイズ制限なし |

**設計上の意図**: SDK は zero-dependency。トランスポートのセキュリティはユーザ実装の責務。この設計は合理的だが、ユーザが安全でないトランスポートを実装するリスクがある。

**推奨対策（ドキュメント強化）**:
ユーザ向けに以下のガイドラインを提供：
- gRPC クライアントは必ず TLS チャネルを使用すること
- API key は metadata 経由で設定すること
- レスポンスサイズの上限を設定すること

### 5. shutdown 後の操作防止

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ingest() の拒否 | **OK** | `index.ts:138` — `if (this.isShutdown) throw new Error(...)` |
| onTaskAction() の拒否 | **OK** | `index.ts:176` — `if (this.isShutdown) throw new Error(...)` |
| updateCallbacks() の拒否 | **OK** | `index.ts:224` — `if (this.isShutdown) throw new Error(...)` |
| shutdown の冪等性 | **OK** | `index.ts:116` — `if (this.isShutdown) return` |

### 6. 二重初期化防止

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 重複 initialize() の警告 | **OK** | `index.ts:70-73` — 既存インスタンスを返却し、警告ログ |
| 既存インスタンスの返却 | **OK** | 新規インスタンスは作成しない（設定の上書きを防止） |

---

## 攻撃シナリオ分析

### シナリオ1: 悪意あるトランスポート実装

ユーザが悪意ある（または脆弱な）`RemoteTransport` を実装した場合：

- `send()` が永遠にハングする → **対策済み**: 30秒タイムアウト
- `send()` が巨大な `IngestionResult` を返す → **未対策**: 応答サイズ制限なし
- `send()` がプロトタイプ汚染オブジェクトを返す → **一部対策**: 返却値はそのまま呼び出し元に渡される
- `close()` が例外を投げる → **対策済み**: `index.ts:119-123` で `catch` して無視

**推奨対策**:
- 応答サイズ制限は実装コストに対してリスクが低いため、優先度は低い
- ユーザ実装のトランスポートは信頼する設計方針で問題ない（SDK はライブラリであり、ユーザコードは信頼境界内）

### シナリオ2: 中間者攻撃 (MITM)

- SDKからGoサーバへの通信がTLS未設定の場合、ログ内容が傍受される可能性
- **責任範囲**: トランスポート実装者の責務。SDK は強制しない
- **推奨**: ドキュメントに TLS 必須の旨を明記

---

## 総合判定

**評価: B+（良好）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| タイムアウト制御 | — | **OK** | 30秒デフォルト + cleanup |
| フォールバック時のエラーロスト | MEDIUM | **要改善** | transportError の伝播が不完全 |
| TLS/認証の非強制 | LOW | **設計上の選択** | ドキュメント強化で対応 |
| shutdown後の操作防止 | — | **OK** | 全API境界で検証済み |
| 応答サイズ制限なし | LOW | **許容** | 信頼境界内のユーザコード |
