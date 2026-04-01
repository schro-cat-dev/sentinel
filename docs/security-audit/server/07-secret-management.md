# Go Server シークレット管理・環境変数セキュリティ監査

## 概要

Go サーバにおけるシークレット（APIキー、HMAC キー、暗号化キー、Webhook 秘密鍵、SMTP パスワード等）の管理状況を評価する。

---

## シークレット一覧

| シークレット | 環境変数 | 用途 | 最低要件 |
|-------------|---------|------|---------|
| HMAC Key | `SENTINEL_HMAC_KEY` | ハッシュチェーン署名 | 32バイト以上 |
| API Keys | `SENTINEL_API_KEYS` | gRPC認証 | 16文字以上 |
| DB Encryption Key | `SENTINEL_STORE_ENCRYPTION_KEY` | SQLCipher暗号化 | 32バイト以上 |
| Webhook Secret | `SENTINEL_WEBHOOK_SECRET` | Webhook HMAC署名 | なし（任意） |
| Slack Webhook URL | `SENTINEL_SLACK_WEBHOOK_URL` | Slack通知 | — |
| Discord Webhook URL | `SENTINEL_DISCORD_WEBHOOK_URL` | Discord通知 | — |
| Gmail Password | `SENTINEL_GMAIL_PASSWORD` | SMTP認証 | — |

---

## チェック項目一覧

### 1. シークレットの読み込みと検証

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| HMAC Key 最低長検証 | **OK** | `config.go` — 32バイト以上 |
| API Key 最低長検証 | **OK** | `config.go` — 16文字以上 |
| Encryption Key 最低長検証 | **OK** | `config.go` — 32バイト以上 |
| **HMAC Key 空文字列チェック** | **OK** | `signer.go:34` — `len(hmacKey) == 0` でエラー |
| **起動時のフェイルファスト** | **OK** | 検証失敗でプロセス終了 |

### 2. シークレットのメモリ上の取り扱い

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| HMAC Key のメモリ保管 | **注意** | `[]byte` としてヒープに保管。GC後もメモリに残留可能 |
| API Key のメモリ保管 | **注意** | `map[string]bool` として保管 |
| **メモリ上のシークレット消去** | **NG** | shutdown時にシークレットを明示的にゼロクリアしない |

**メモリ残留リスク**:
- Go のGCはメモリの内容をゼロクリアしない
- メモリダンプやコアダンプからシークレットが漏洩する可能性
- **緩和**: プロセスのメモリへのアクセスは特権操作が必要

**推奨対策** (高セキュリティ要件の場合):
```go
// shutdown時にシークレットをゼロクリア
func (s *IntegritySigner) ClearKeys() {
    s.mu.Lock()
    defer s.mu.Unlock()
    for i := range s.hmacKey {
        s.hmacKey[i] = 0
    }
    for i := range s.previousKeys {
        for j := range s.previousKeys[i] {
            s.previousKeys[i][j] = 0
        }
    }
}
```

### 3. ログへのシークレット漏洩

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| HMAC Key のログ出力 | **OK** | ログに出力されない |
| API Key のログ出力 | **OK** | ログに出力されない |
| Encryption Key のログ出力 | **OK** | ログに出力されない |
| DSN のログ出力 | **OK** | ドライバ名のみログ出力 |
| Webhook URL のログ出力 | **注意** | `main.go:232` — URL がログに出力される。URLにトークンが含まれる場合リスクあり |
| Gmail From のログ出力 | **注意** | `main.go:258` — メールアドレスがログに出力される |

**Webhook URL リスク**: Slack/Discord のWebhook URLには認証トークンが含まれる（例: `https://hooks.slack.com/services/T.../B.../xxx`）。このURLがログに出力されるとトークンが漏洩する。

**推奨パッチ**:
```go
// URL のトークン部分をマスクしてログ出力
func maskURL(rawURL string) string {
    u, err := url.Parse(rawURL)
    if err != nil {
        return "[INVALID_URL]"
    }
    // パスの最後のセグメントをマスク
    parts := strings.Split(u.Path, "/")
    if len(parts) > 1 {
        parts[len(parts)-1] = "***"
    }
    u.Path = strings.Join(parts, "/")
    return u.String()
}

// main.go
slog.Info("webhook notifier registered", "url", maskURL(cfg.Webhook.URL))
```

### 4. 設定ファイルのセキュリティ

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| .gitignore | **OK** | `.env`, `.security/` が除外 |
| 設定ファイル例 | **OK** | `sentinel.config.yaml.example` — プレースホルダ使用 |
| **設定ファイルのパーミッション** | **未設定** | ファイルパーミッションのチェックなし |

**推奨パッチ**:
```go
// config.go — 設定ファイルのパーミッションチェック
func Load(path string) (*Config, error) {
    info, err := os.Stat(path)
    if err != nil {
        return nil, err
    }
    // 他ユーザが読み取り可能な場合は警告
    if info.Mode().Perm()&0044 != 0 {
        slog.Warn("config file is world/group-readable — consider restricting permissions",
            "path", path, "mode", info.Mode().String())
    }
    // ...
}
```

### 5. シークレットの分類と保護レベル

| シークレット | 保護レベル | 推奨保護レベル | ギャップ |
|-------------|-----------|--------------|---------|
| HMAC Key | 環境変数 | Vault/Secret Manager | **あり** |
| API Keys | 環境変数 | Vault/Secret Manager | **あり** |
| DB Encryption Key | 環境変数 | Vault/Secret Manager | **あり** |
| Webhook Secret | 環境変数 | 環境変数/Vault | 低い |
| Slack/Discord URL | 環境変数 | Vault/Secret Manager | **あり** |
| Gmail Password | 環境変数 | Vault/OAuth2 | **あり** |

### 6. シークレットローテーション

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| HMAC Key ローテーション | **OK** | `signer.go:85-110` — `AddPreviousKey()` + `VerifyHashWithRotation()` |
| API Key ローテーション | **NG** | 動的なキー追加/削除機構なし。再起動が必要 |
| DB Encryption Key ローテーション | **NG** | SQLCipher の re-key は手動操作 |

---

## 環境変数のセキュリティ

### 7. 環境変数の注入

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| `applyEnvOverrides()` の安全性 | **OK** | 特定の環境変数名のみ読み取り |
| カンマ区切りAPI Keysのパース | **OK** | `strings.TrimSpace` で安全にパース |
| **空の環境変数への対応** | **OK** | 空文字列の場合はデフォルト値を維持 |

### 8. コンテナ環境での考慮事項

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| Docker secrets | **非対応** | ファイルベースのシークレット読み込みなし |
| Kubernetes secrets | **非対応** | 環境変数としてマウントされるため動作するが、ファイルマウントは非対応 |

**推奨**: `config.go` にファイルベースのシークレット読み込みを追加
```go
// ファイルベースシークレット（Docker/K8s対応）
func loadSecret(envKey, filePath string) string {
    if v := os.Getenv(envKey); v != "" {
        return v
    }
    if filePath != "" {
        data, err := os.ReadFile(filePath)
        if err == nil {
            return strings.TrimSpace(string(data))
        }
    }
    return ""
}
```

---

## 総合判定

**評価: B-（改善推奨）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| シークレット検証 | — | **OK** | 最低長チェックあり |
| Webhook URLのログ出力 | MEDIUM | **要改善** | トークンマスク追加 |
| シークレット管理サービス未統合 | MEDIUM | **要改善** | Vault等の導入推奨 |
| メモリ上のシークレット消去 | LOW | **要改善** | 高セキュリティ要件時 |
| 設定ファイルパーミッション | LOW | **要改善** | 警告追加 |
| API Key動的ローテーション | LOW | **要改善** | 再起動不要な機構 |
| コンテナシークレット対応 | LOW | **要改善** | ファイルベース読み込み |
