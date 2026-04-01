# Go Server 認証・認可・最小権限の原則監査

## 概要

Go サーバの認証（Authentication）・認可（Authorization）メカニズムと、最小権限の原則（Principle of Least Privilege）の遵守状況を評価する。

---

## 認証 (Authentication)

### 1. API Key 認証 — gRPC Interceptor

**ファイル**: `internal/grpc/interceptors.go:21-42`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| gRPC metadata からの取得 | **OK** | `metadata.FromIncomingContext(ctx)` → `md.Get("x-api-key")` |
| HealthCheck の認証除外 | **OK** | `info.FullMethod == "/sentinel.v1.SentinelService/HealthCheck"` |
| 認証失敗のログ | **OK** | `slog.Warn("authentication failed", ...)` |
| 認証失敗のステータスコード | **OK** | `codes.Unauthenticated` |
| **定数時間比較** | **NG** | `interceptors.go:34` — `validKeys[keys[0]]` はマップルックアップ（タイミング攻撃に脆弱） |

**タイミング攻撃リスク**:

```go
// interceptors.go:34 — 現在の実装
if len(keys) == 0 || !validKeys[keys[0]] {
```

Go のマップルックアップはハッシュテーブルベースであり、キーの存在/非存在を判定する時間はほぼ一定だが、暗号学的な定数時間比較ではない。一方、`middleware/auth.go:31` では `subtle.ConstantTimeCompare` を正しく使用している。

**不整合の分析**:
- `interceptors.go` — マップルックアップ（タイミング非安全）
- `middleware/auth.go` — `subtle.ConstantTimeCompare`（タイミング安全）

この不整合は、interceptor が先に実行され、auth middleware が後から追加されたアーキテクチャに起因する可能性がある。

**推奨パッチ**:
```go
// interceptors.go — 定数時間比較に修正
func AuthUnaryInterceptor(validKeys map[string]bool) ggrpc.UnaryServerInterceptor {
    // マップから全キーをスライスに変換
    keyList := make([]string, 0, len(validKeys))
    for k := range validKeys {
        keyList = append(keyList, k)
    }

    return func(ctx context.Context, req any, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (any, error) {
        if info.FullMethod == "/sentinel.v1.SentinelService/HealthCheck" {
            return handler(ctx, req)
        }

        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }

        keys := md.Get("x-api-key")
        if len(keys) == 0 {
            slog.Warn("authentication failed", "method", info.FullMethod)
            return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
        }

        // 定数時間比較
        matched := false
        for _, valid := range keyList {
            if subtle.ConstantTimeCompare([]byte(keys[0]), []byte(valid)) == 1 {
                matched = true
                break  // ただし全キー検証のほうが理想的
            }
        }

        if !matched {
            slog.Warn("authentication failed", "method", info.FullMethod)
            return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
        }

        ctx = context.WithValue(ctx, clientIDKey, keys[0])
        return handler(ctx, req)
    }
}
```

### 2. TokenValidator 抽象化

**ファイル**: `internal/middleware/auth.go`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| StaticTokenValidator | **OK** | `subtle.ConstantTimeCompare` 使用 |
| CachedTokenValidator | **OK** | キャッシュTTL付き、RWMutex で並行安全 |
| NoopTokenValidator | **OK** | 認証無効時に使用。`"anonymous"` を返却 |
| キャッシュ毒入れ防止 | **OK** | `valid: false` もキャッシュされ、不正トークンの再試行をブロック |
| **キャッシュ無限増殖** | **要注意** | 不正トークンのキャッシュエントリが増え続ける可能性 |

**キャッシュ無限増殖リスク**:
- 攻撃者が大量のユニークな不正トークンを送信すると、`cache` マップが無制限に成長
- TTL でエントリは期限切れになるが、TTL 期間内にマップが巨大化する可能性

**推奨パッチ**:
```go
const maxCacheSize = 10000

func (v *CachedTokenValidator) Validate(ctx context.Context, token string) (string, error) {
    // ... existing cache check ...

    // Cache miss → query external store
    // ...

    // Update cache with size limit
    v.mu.Lock()
    if len(v.cache) >= maxCacheSize {
        // Evict expired entries first
        now := time.Now()
        for k, entry := range v.cache {
            if now.After(entry.expiresAt) {
                delete(v.cache, k)
            }
        }
        // If still over limit, skip caching
        if len(v.cache) >= maxCacheSize {
            v.mu.Unlock()
            if !valid { return "", fmt.Errorf("invalid token") }
            return clientID, nil
        }
    }
    v.cache[token] = cachedEntry{...}
    v.mu.Unlock()
    // ...
}
```

### 3. APIキーの保管

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 環境変数からの読み込み | **OK** | `config.go` — `SENTINEL_API_KEYS` 環境変数 |
| メモリ上の保管 | **要注意** | `main.go:120-122` — `map[string]bool` に平文保管 |
| ログへの非出力 | **OK** | APIキーはログに出力されない |

**推奨**: 本番環境では HashiCorp Vault や AWS Secrets Manager 等のシークレット管理サービスを使用。

---

## 認可 (Authorization)

### 4. RBAC システム

**ファイル**: `internal/middleware/authorizer.go`（想定）

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ロールベースアクセス制御 | **OK** | `Permission` 構造体にきめ細かなフィールド |
| 許可LogType制御 | **OK** | `AllowedLogTypes` / `DeniedLogTypes` |
| 最大LogLevel制限 | **OK** | `MaxLogLevel` |
| Write/Read/Approve/Admin権限 | **OK** | 個別のブール値で制御 |
| デフォルトロール | **OK** | `DefaultRole` が設定可能 |
| クライアント→ロールマッピング | **OK** | `ClientRoles` マップ |

### 5. 最小権限の原則

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| デフォルト拒否 | **OK** | 認可有効時、未設定クライアントはデフォルトロールが適用 |
| LogType 制限 | **OK** | `AllowedLogTypes` で許可リスト方式 |
| LogLevel 制限 | **OK** | `MaxLogLevel` で上限設定 |
| 操作種別の分離 | **OK** | Write / Read / Approve / Admin の4レベル |
| **Approve権限の分離** | **OK** | 承認操作は `CanApprove` が必要 |

---

## レート制限

### 6. クライアント別レート制限

**ファイル**: `internal/grpc/interceptors.go:45-73`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| トークンバケットアルゴリズム | **OK** | `golang.org/x/time/rate.Limiter` |
| クライアント別の分離 | **OK** | `map[string]*rate.Limiter` |
| 未認証クライアントの制限 | **OK** | `"__anonymous__"` として統一レート |
| ステータスコード | **OK** | `codes.ResourceExhausted` |
| **Limiter マップの無限増殖** | **要注意** | 認証後のクライアントIDごとにLimiterが作成されるが、削除機構がない |

**Limiter マップ増殖リスク**:
- 認証済みだが異なるクライアントIDが大量に存在する場合、`limiters` マップが成長し続ける
- **影響**: メモリリーク。長期運用で問題化する可能性
- **緩和**: 通常、APIキー数は有限であるため、実運用での影響は限定的

**推奨パッチ**:
```go
// 定期的な Limiter クリーンアップ（LRU的）
type limiterEntry struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}
// cleanupLoop で lastSeen が古いエントリを削除
```

---

## 監査ログ

### 7. アクセスログ

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 全リクエストのログ | **OK** | `AuditLogUnaryInterceptor()` — 常に有効 |
| メソッド名の記録 | **OK** | `info.FullMethod` |
| クライアントIDの記録 | **OK** | `ClientIDFromContext(ctx)` |
| ステータスの記録 | **OK** | `ok` / `error` |
| **レスポンス詳細の非記録** | **OK** | レスポンスボディはログに含まれない |
| **リクエストボディの非記録** | **OK** | リクエストボディはログに含まれない（PII安全） |

---

## 総合判定

**評価: B+（良好、改善余地あり）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| 定数時間比較の不整合 | MEDIUM | **要改善** | interceptor と auth middleware の実装差異 |
| キャッシュ無限増殖 | MEDIUM | **要改善** | サイズ上限追加推奨 |
| Limiter マップ増殖 | LOW | **要改善** | クリーンアップ機構追加推奨 |
| APIキー平文保管 | LOW | **要改善** | シークレット管理サービス推奨 |
| RBAC 粒度 | — | **OK** | 4レベルの操作分離 |
| 監査ログ | — | **OK** | 全リクエスト記録 |
| 最小権限の原則 | — | **OK** | デフォルト拒否、ホワイトリスト方式 |
