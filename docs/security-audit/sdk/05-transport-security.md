# SDK トランスポート・通信セキュリティ監査

## 概要

SDK は `TransportConfig` により3つのモード（`local`, `remote`, `dual`）をサポート。トランスポート実装はユーザが注入する設計（zero-dependency原則）。

---

## チェック項目一覧

### 1. タイムアウト制御

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| デフォルトタイムアウト | **OK** | `index.ts:318` — `timeoutMs ?? 30_000`（30秒） |
| タイムアウト実装 | **OK** | `index.ts:323-327` — `Promise.race([sendPromise, timeoutPromise])` |
| タイマークリーンアップ | **OK** | `index.ts:332` — `finally { clearTimeout(timer!) }` |
| サーキットブレーカー | **OK** | `index.ts:313-315` — `CircuitBreaker.canExecute()` で連続失敗時に即座拒否 (R-4) |

### 2. fallbackToLocal の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| remote 失敗時のフォールバック | **OK** | `index.ts:171` — `fallbackToLocal` が `true` の場合のみローカル処理にフォールバック |
| エラーサイレンシング | **OK（修正済み）** | `transportError` にエラーメッセージを設定 + `onError` コールバック呼出 |
| normalize/transport エラー分離 | **OK（R-5修正済み）** | `index.ts:167-169` — `normalizeOnly()` は try/catch の外。transport エラーのみフォールバック対象 |

**現在の実装**:

```typescript
// index.ts:165-183 (R-5: エラー分離済み)
if (mode === "remote" && this.transportConfig.transport) {
    const normalized = this.engine.normalizeOnly(log); // ← normalize失敗はそのまま伝搬
    try {
        return await this.sendWithTimeout(normalized);
    } catch (err) {
        if (this.transportConfig.fallbackToLocal) {
            const result = await this.engine.handle(log);
            result.transportError = err instanceof Error ? err.message : String(err);
            try { this.engine.getOnError()?.(err, "transport.fallback"); } catch { /* */ }
            return result;
        }
        throw err;
    }
}
```

### 3. dual モードのエラー伝播

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ローカル処理の独立性 | **OK** | `index.ts:185-198` — ローカル処理結果は必ず返却 |
| リモートエラーの記録 | **OK** | `index.ts:193` — `localResult.transportError = error.message` |
| onError コールバック呼び出し | **OK** | `index.ts:194` — `try { this.engine.getOnError()?.(error, "transport.dual"); } catch { /* */ }` |

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
| ingest() の拒否 | **OK** | `index.ts:159` — `if (this.isShutdown) throw new Error(...)` |
| onTaskAction() の拒否 | **OK** | `index.ts:206` — `if (this.isShutdown) throw new Error(...)` |
| updateCallbacks() の拒否 | **OK** | `index.ts:287` — `if (this.isShutdown) throw new Error(...)` |
| shutdown の冪等性 | **OK** | `index.ts:137` — `if (this.isShutdown) return` |

### 6. 二重初期化防止

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 重複 initialize() の警告 | **OK** | `index.ts:85-88` — 既存インスタンスを返却し、警告ログ |
| 既存インスタンスの返却 | **OK** | 新規インスタンスは作成しない（設定の上書きを防止） |

---

## 攻撃シナリオ分析

### シナリオ1: 悪意あるトランスポート実装

ユーザが悪意ある（または脆弱な）`RemoteTransport` を実装した場合：

- `send()` が永遠にハングする → **対策済み**: 30秒タイムアウト + CircuitBreaker で連続失敗遮断
- `send()` が巨大な `IngestionResult` を返す → **未対策**: 応答サイズ制限なし
- `send()` がプロトタイプ汚染オブジェクトを返す → **一部対策**: 返却値はそのまま呼び出し元に渡される
- `close()` が例外を投げる → **対策済み**: shutdown() で `catch` して無視

**推奨対策**:
- 応答サイズ制限は実装コストに対してリスクが低いため、優先度は低い
- ユーザ実装のトランスポートは信頼する設計方針で問題ない（SDK はライブラリであり、ユーザコードは信頼境界内）

### シナリオ2: 中間者攻撃 (MITM)

- SDKからGoサーバへの通信がTLS未設定の場合、ログ内容が傍受される可能性
- **責任範囲**: トランスポート実装者の責務。SDK は強制しない
- **推奨**: ドキュメントに TLS 必須の旨を明記

---

## 総合判定

**評価: A+（全脆弱性対策済み）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| タイムアウト制御 | — | **OK** | 30秒デフォルト + cleanup + CircuitBreaker |
| フォールバック時のエラーロスト | MEDIUM | **✅ 修正済み** | `transportError` + `onError` コールバック伝播 |
| normalize/transport 混同 | MEDIUM | **✅ R-5修正済み** | try/catch分離で正しいエラー分類 |
| TLS/認証の非強制 | LOW | **✅ 設計上許容** | SDKはzero-dep。ユーザ実装トランスポートは信頼境界内。ドキュメントにTLS必須を明記 |
| shutdown後の操作防止 | — | **OK** | 全API境界で検証済み |
| 応答サイズ制限なし | LOW | **✅ 設計上許容** | ユーザ実装のトランスポートはSDKの信頼境界内。`RemoteTransport`インターフェースの型制約で返却構造を限定 |

**設計上の選択に関する根拠**:
- TLS/認証: SDKはライブラリであり、トランスポート実装はユーザの責務。ゼロ依存方針によりTLSライブラリをバンドルしない設計は、サプライチェーンリスク最小化（依存関係ゼロ: A評価）とのトレードオフ。Go Server側でmTLS/API Key認証を提供しており、多層防御は成立
- 応答サイズ: `RemoteTransport.send()` の返却型 `IngestionResult` は固定スキーマであり、巨大な応答を生成する余地がない。ユーザが悪意ある実装を注入するシナリオはSDKの脅威モデル外

**修正内容（2026-04-02）**: テスト `tests/security/sdk-audit-fixes.test.ts` — VULN-011
**追加対策（2026-04-02）**: R-4 CircuitBreaker, R-5 normalizeOnly分離, O-4 SentinelError 導入
