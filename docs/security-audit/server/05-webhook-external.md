# Go Server Webhook・外部連携セキュリティ監査

## 概要

Webhook 通知、Slack/Discord/Gmail アダプタ、外部AI Agentとの連携セキュリティを評価する。

---

## チェック項目一覧

### 1. Webhook Notifier のセキュリティ

**ファイル**: `internal/webhook/notifier.go`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| HMAC 署名 | **OK** | `notifier.go:79-84` — `hmac.New(sha256.New, n.secret)` |
| 署名ヘッダ | **OK** | `X-Sentinel-Signature` |
| Content-Type | **OK** | `application/json` |
| HTTP タイムアウト | **OK** | `http.Client.Timeout` で設定 |
| レスポンスボディの処理 | **OK** | `resp.Body.Close()` — defer で確実にclose |
| **リトライ機構** | **NG** | 失敗時にリトライしない。通知がロストする可能性 |
| **証明書検証** | **OK** | Go の `http.Client` デフォルトでシステムCAを検証 |
| **SSRF (Server-Side Request Forgery)** | **要注意** | Webhook URLが設定ファイルから読み込まれるため、内部ネットワークURLの指定が可能 |

**SSRF リスク分析**:
- Webhook URL は設定ファイルから読み込まれる
- 設定ファイルにアクセスできる攻撃者が内部URLを指定する可能性
- 例: `http://169.254.169.254/latest/meta-data/` (AWS メタデータエンドポイント)
- **緩和**: 設定ファイルは管理者のみがアクセス可能

**推奨パッチ** (SSRF防御を強化する場合):
```go
import "net"

func validateWebhookURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid webhook URL: %w", err)
    }

    // ローカルネットワークのブロック
    host := u.Hostname()
    ips, err := net.LookupIP(host)
    if err != nil {
        return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
    }
    for _, ip := range ips {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return fmt.Errorf("webhook URL resolves to private/local address: %s", ip)
        }
    }
    return nil
}
```

### 2. 通知アダプタの安全性

#### Slack Notifier

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| Webhook URL の安全性 | **OK** | HTTPS のみ（Slack Webhook URLは https://hooks.slack.com/...） |
| ペイロードのサニタイゼーション | **要確認** | Slack メッセージ内のユーザ入力がインジェクションされる可能性（mentionやリンク） |
| タイムアウト | **OK** | HTTP クライアントタイムアウト |

#### Discord Notifier

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| Webhook URL の安全性 | **OK** | HTTPS のみ |
| ペイロードのサニタイゼーション | **要確認** | Discord マークダウンインジェクションの可能性 |
| タイムアウト | **OK** | HTTP クライアントタイムアウト |

#### Gmail Notifier

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| SMTP 認証 | **OK** | `smtp.PlainAuth` |
| **TLS** | **要確認** | `smtp.SendMail` はSTARTTLSをサポートするが、強制かどうかは実装次第 |
| パスワードの保管 | **OK** | 環境変数から読み込み |
| **メールヘッダインジェクション** | **要確認** | Subject/Body にユーザ入力が含まれる場合、ヘッダインジェクションリスク |

**メールヘッダインジェクション対策**:
```go
// Subject から改行文字を除去
func sanitizeEmailSubject(s string) string {
    return strings.NewReplacer("\r", "", "\n", "", "\r\n", "").Replace(s)
}
```

### 3. 外部AI Agent 連携

**ファイル**: `internal/agent/executor.go`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ループ深度制限 | **OK** | `MaxLoopDepth` (デフォルト5) |
| タイムアウト | **OK** | `TimeoutSec` (デフォルト60秒) |
| Origin検出によるループ防止 | **OK** | `AI_AGENT` originのログは再処理をスキップ |
| **プロバイダURL検証** | **要確認** | MockProvider使用中。実プロバイダ導入時にURL検証が必要 |
| **レスポンスサイズ制限** | **要確認** | AIプロバイダからのレスポンスサイズ制限 |

### 4. Webhook 秘密鍵の管理

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 環境変数からの読み込み | **OK** | `SENTINEL_WEBHOOK_SECRET` |
| 秘密鍵なしでの動作 | **OK** | `len(n.secret) > 0` — 秘密鍵なしの場合、署名ヘッダを付与しない |
| **秘密鍵なしの警告** | **NG** | 秘密鍵なしで Webhook を有効化しても警告が出ない |

**推奨パッチ**:
```go
// main.go で Webhook 初期化時
if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
    if cfg.Webhook.Secret == "" {
        slog.Warn("webhook enabled without HMAC secret — requests will not be signed",
            "url", cfg.Webhook.URL)
    }
    notifier = webhook.NewNotifier(cfg.Webhook.URL, cfg.Webhook.TimeoutSec, cfg.Webhook.Secret)
}
```

### 5. 通知ルーティング

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| プレフィックスマッチング | **OK** | `SetRouting(prefix, providers)` |
| マルチプロバイダ送信 | **OK** | `MultiNotifier` が複数プロバイダに配信 |
| フォールバック (LogNotifier) | **OK** | 常にログ出力プロバイダが登録 |
| **通知失敗の伝播** | **OK** | エラーを返却。呼び出し元で処理 |

---

## 外部連携フロー図

```
[Sentinel Pipeline]
    ↓ ThreatResponse detected
[ResponseOrchestrator]
    ↓ WithNotifyFunc
[MultiNotifier]
    ├─ LogNotifier (always)
    ├─ WebhookNotifier (HMAC-signed POST)
    ├─ SlackNotifier (Incoming Webhook)
    ├─ DiscordNotifier (Webhook)
    └─ GmailNotifier (SMTP)

[Webhook Notifier (Approval)]
    ↓ NotifyApprovalRequired
    ↓ go func() { send() }  ← fire-and-forget goroutine
```

---

## 総合判定

**評価: B（良好、改善推奨）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| HMAC署名 | — | **OK** | SHA-256 |
| HTTPタイムアウト | — | **OK** | |
| リトライ機構 | MEDIUM | **NG** | 通知ロストリスク |
| SSRF防御 | LOW | **要改善** | 設定ファイル管理でリスク緩和中 |
| メールヘッダインジェクション | LOW | **要確認** | Subject のサニタイゼーション |
| Webhook秘密鍵なし警告 | LOW | **NG** | 警告追加推奨 |
| AI Agent レスポンスサイズ | LOW | **要確認** | 実プロバイダ導入時に対応 |
