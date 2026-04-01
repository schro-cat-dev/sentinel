# Go Server gRPC・ネットワークプロトコルセキュリティ監査

## 概要

gRPC サーバの TLS 設定、メッセージサイズ制限、インターセプターチェーン、セキュリティヘッダの評価。

---

## チェック項目一覧

### 1. TLS 設定

**ファイル**: `cmd/server/main.go:136-144`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| TLS サポート | **OK** | `credentials.NewServerTLSFromFile()` |
| TLS のオプション化 | **OK** | cert/key ファイルが設定されていない場合はプレーンテキスト |
| 証明書読み込みエラー時のフェイルファスト | **OK** | `os.Exit(1)` |
| **TLS バージョン制限** | **注意** | gRPC-Go デフォルトは TLS 1.2+。明示的な `MinVersion` 設定なし |
| **暗号スイートの制限** | **注意** | デフォルトの暗号スイートを使用。カスタマイズなし |
| **mTLS (相互TLS)** | **非対応** | クライアント証明書の検証なし |

**推奨パッチ**（TLS設定の強化が必要な場合）:
```go
import "crypto/tls"

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    },
}
creds := credentials.NewTLS(tlsConfig)
```

### 2. メッセージサイズ制限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 受信メッセージサイズ | **OK** | `MaxRecvMsgSizeBytes` — 設定可能 |
| 同時ストリーム数 | **OK** | `MaxConcurrentStreams` — 設定可能 |
| **デフォルト値** | **要確認** | gRPC-Go デフォルトは 4MB。設定ファイルで明示的に制限推奨 |

### 3. インターセプターチェーン

**ファイル**: `cmd/server/main.go:114-128`

| 順序 | インターセプター | 条件 | 評価 |
|------|----------------|------|------|
| 1 | `AuditLogUnaryInterceptor()` | 常に有効 | **OK** — 全リクエストをログ |
| 2 | `AuthUnaryInterceptor(keyMap)` | `cfg.Auth.Enabled` | **OK** — 認証 |
| 3 | `RateLimitUnaryInterceptor(rps, burst)` | `cfg.Auth.Enabled` | **OK** — レート制限 |

**チェーン順序の安全性**:

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 監査ログの先行 | **OK** | 認証前に監査ログが記録される → 不正アクセスも記録 |
| 認証後のレート制限 | **OK** | 認証済みクライアントIDに基づくレート制限 |
| **認証無効時のレート制限** | **NG** | `cfg.Auth.Enabled == false` の場合、レート制限も無効 |

**認証無効時のレート制限リスク**:
- 認証が無効 (`Auth.Enabled: false`) の場合、レート制限も一緒にスキップされる
- **影響**: 認証を無効にした開発/テスト環境でDoS攻撃を受ける可能性

**推奨パッチ**:
```go
// レート制限は認証とは独立して設定可能にする
interceptors = append(interceptors, sentinelgrpc.AuditLogUnaryInterceptor())

if cfg.Auth.Enabled {
    // ... auth interceptor ...
}

// レート制限は常に適用（設定で無効化可能）
if cfg.Auth.RateLimitRPS > 0 {
    interceptors = append(interceptors,
        sentinelgrpc.RateLimitUnaryInterceptor(cfg.Auth.RateLimitRPS, cfg.Auth.RateLimitBurst),
    )
}
```

### 4. Graceful Shutdown

**ファイル**: `cmd/server/main.go:288-304`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| シグナルハンドリング | **OK** | `SIGINT`, `SIGTERM` |
| タイムアウト付きgraceful stop | **OK** | `context.WithTimeout` + `srv.GracefulStop()` |
| タイムアウト時の強制停止 | **OK** | `srv.Stop()` |
| **データベース close** | **OK** | `defer st.Close()` — main の defer で確実に close |

### 5. HealthCheck エンドポイント

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 認証の除外 | **OK** | interceptor で明示的にスキップ |
| 情報漏洩 | **OK** | HealthCheck は "SERVING" ステータスのみ返却 |
| **バージョン情報の漏洩** | **OK** | HealthCheck にバージョン情報は含まれない |

---

## セキュリティヘッダ（HTTP/gRPC）

gRPC は HTTP/2 ベースだが、通常のHTTPヘッダとは異なる。Go サーバの `middleware/` に SecurityConfig が存在するが、gRPC インターセプターとしては適用されていない（HTTP ミドルウェア向け）。

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| gRPC レスポンスへのセキュリティヘッダ | **N/A** | gRPC はヘッダ操作が限定的。HTTPゲートウェイ使用時のみ関係 |
| CORS 制御 | **N/A** | gRPC は通常CORS不要（ブラウザからの直接接続なし） |

---

## 入力サニタイゼーション（gRPC レイヤー）

### 6. protobuf メッセージの安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| protobuf の自動バリデーション | **OK** | protobuf はスキーマに基づく型安全なデシリアライゼーション |
| unknown フィールドの処理 | **OK** | protobuf v3 はデフォルトで unknown fields を無視 |
| 巨大メッセージの拒否 | **OK** | `MaxRecvMsgSizeBytes` で制限 |

### 7. server.go のアプリケーション層バリデーション

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| message 必須チェック | **OK** | server.go で空メッセージを拒否 |
| type ホワイトリスト | **OK** | `sanitizer.go` の `ValidateLogType()` |
| origin ホワイトリスト | **OK** | `sanitizer.go` の `ValidateOrigin()` |
| null byte チェック | **OK** | `sanitizer.go` の `ValidateString()` |
| **二重バリデーション** | **OK** | protobuf 型チェック + アプリケーション層バリデーション |

---

## 総合判定

**評価: B+（良好）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| TLS サポート | — | **OK** | |
| TLS バージョン/暗号スイートの明示化 | LOW | **要改善** | セキュリティ要件次第 |
| mTLS 非対応 | LOW | **許容** | 用途次第 |
| 認証無効時のレート制限スキップ | MEDIUM | **要改善** | 独立した設定推奨 |
| インターセプターチェーン順序 | — | **OK** | |
| Graceful Shutdown | — | **OK** | |
| 入力サニタイゼーション | — | **OK** | 多層防御 |
