# サーバサイド (Go) — セキュリティ所見

**スコープ:** `packages/server/`
**最終監査:** 2026-03-30

---

## S-001: HMAC鍵の最小長未検証 (CRITICAL)

**ファイル:** `packages/server/config/config.go`
**CWE:** CWE-326 (Inadequate Encryption Strength)

### 問題
`SENTINEL_HMAC_KEY` 環境変数に最小長検証がない。空文字列やn短い鍵でもサーバが起動し、
ハッシュチェーンの完全性検証が事実上無効になる。

### 影響
- ログの改竄検知が機能しない
- 短い鍵へのブルートフォース攻撃

### 対策
```go
func (c *Config) Validate() error {
    if len(c.Security.HMACKey) < 32 {
        return fmt.Errorf("SENTINEL_HMAC_KEY must be at least 32 bytes (got %d)", len(c.Security.HMACKey))
    }
    return nil
}
```

---

## S-002: API Key空文字列による認証バイパス (CRITICAL)

**ファイル:** `packages/server/config/config.go`
**CWE:** CWE-287 (Improper Authentication)

### 問題
`SENTINEL_API_KEYS` をカンマ分割する際、空文字列がフィルタされない。
`"key1,,key2"` → `["key1", "", "key2"]` となり、空文字列で認証が通過する。

### 対策
```go
for _, k := range strings.Split(raw, ",") {
    k = strings.TrimSpace(k)
    if k != "" && len(k) >= 32 {
        cfg.Auth.APIKeys = append(cfg.Auth.APIKeys, k)
    }
}
```

---

## S-003: TLSデフォルト無効 (HIGH)

**ファイル:** `packages/server/config/sentinel.yaml:6-7`
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

### 問題
```yaml
# tls_cert_file: "/path/to/cert.pem"   # TLS有効化（空=plaintext）
# tls_key_file: "/path/to/key.pem"
```
デフォルトでTLSが無効。開発環境では便利だが、production modeでの強制がない。

### 対策
- 環境変数 `SENTINEL_ENV=production` 時にTLS必須チェックを追加
- ドキュメントに「本番環境ではTLS必須」を明記

---

## S-004: gRPC insecure credentials (テスト) (HIGH)

**ファイル:** 複数テストファイル
**CWE:** CWE-319

### 問題
テストコードで `insecure.NewCredentials()` を使用。パターンが本番コードにコピーされるリスク。

### 対策
テストヘルパー関数に集約し、`// TEST ONLY` コメントを付与。

---

## S-005: SQLCipher暗号化鍵の強度未検証 (HIGH)

**ファイル:** `packages/server/config/sentinel.yaml:79`
**CWE:** CWE-326

### 問題
`sqlite_encrypted` ドライバ使用時の暗号化鍵に最小長・複雑性要件がない。

### 対策
鍵長32バイト以上を強制。エントロピー検証の追加を検討。

---

## S-006: レートリミットが高すぎる (MEDIUM)

**ファイル:** `packages/server/config/security.default.json:34-37`
**CWE:** CWE-770 (Allocation of Resources Without Limits)

### 問題
デフォルト100 RPS / burst 200はセキュリティシステムとしては高い。

### 対策
デフォルトを10 RPS / burst 50に下げ、設定による上書きを許可。

---

## S-007: ヘルスチェック平文ドキュメント (MEDIUM)

**ファイル:** `docs/docker-guide.md`, `docs/usage-guide.md`

### 問題
ドキュメント内の `grpcurl -plaintext` 例が、本番環境でも平文で接続するよう誘導。

### 対策
各例に `# Development only — use TLS in production` を追記。

---

## S-008: Docker Compose内でのplaintext通信 (MEDIUM)

### 問題
Docker Composeの設定例でTLSなしの接続パターンを示している。

### 対策
TLS設定を含むDocker Compose例を追加。

---

## S-009: ログ出力のサニタイゼーション (LOW)

### 問題
サーバサイドのエラーログにユーザー提供データが含まれる可能性。
ログインジェクション (CWE-117) のリスク。

### 対策
ログ出力時に制御文字のエスケープを徹底。

---

## S-010: 監査ログのタイムスタンプ信頼性 (INFO)

### 問題
クライアントから送信されたタイムスタンプをサーバが信頼している場合、
時間軸の改竄によるログ順序操作が可能。

### 対策
サーバ側でタイムスタンプを付与し、クライアントタイムスタンプは参考値として保持。
