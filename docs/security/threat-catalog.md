# Sentinel 脅威カタログ

```yaml
created_at: "2026-04-02"
framework: STRIDE + MITRE ATT&CK + OWASP Top 10 + Supply Chain
status: active
```

## 脅威カテゴリ総覧

### A. 入力層攻撃（SDK API境界）

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| A-01 | Null byte injection | message/tags/resourceIds等にnull byte注入 → ログ切り詰め、WAF回避 | **対策済**: 全文字列フィールドでnull byte検査 | log-validator.ts |
| A-02 | Oversized payload DoS | 巨大message/agentBackLog → メモリ枯渇 | **対策済**: estimateLogSize + maxTotalLogSize (agentBackLog含む) | log-validator.ts |
| A-03 | Type confusion | number型をstring型フィールドに注入 → 予期しない分岐 | **対策済**: 全フィールド型検証（timestamp=ISO8601 string, logicalClock=finite非負number, triggerAgent=boolean）+ normalizer防御的フォールバック | log-validator.ts, log-normalizer.ts |
| A-04 | Prototype pollution (input) | `__proto__` in tags/input → Object.prototype汚染 | **対策済**: tags はkey/category個別検証、MaskingService hasOwnPropertyガード | log-validator.ts, masking-service.ts |
| A-05 | ReDoS via detectionRules | 悪意のあるRegExpパターン → CPU枯渇 | **対策済**: 入力長上限65536 + `/g`/`y`フラグ拒否 + PIIパターン`/g`なし。redos.test.ts + fuzz_test.go（SCALE-08） | event-detector.ts, masking-service.ts |
| A-06 | Unicode normalization bypass | NFC/NFD混在でPIIマスキング回避 | **テスト済**: encoding-bypass.test.ts | masking-service.ts |
| A-07 | XSS/SQLi in log fields | HTMLタグ/SQL文をmessageに注入 | **影響限定**: SDKはHTMLレンダリングしない。Go server側で出力エスケープ必要 | — |

### B. 設定層攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| B-01 | Config mutation post-init | initialize後にconfig書き換え → セキュリティ機能無効化 | **対策済**: deepFreeze | index.ts |
| B-02 | Whitelist level downgrade | strict → off に切り替えてバリデーション回避 | **対策済**: re-initはshutdown必須、二重initは警告 | index.ts |
| B-03 | Prototype pollution (config) | JSON.parse → __proto__ in config → グローバル汚染 | **対策済**: WhitelistRegistry + taskGenerator に hasOwnPropertyガード | whitelist-registry.ts |
| B-04 | Handler injection | onTaskActionで悪意のあるhandler登録 → 任意コード実行 | **設計上許容**: handler登録はSDK利用者の責任。whitelistでactionType検証 | index.ts |
| B-05 | Callback injection via updateCallbacks | 不正キー/型注入 | **対策済**: VALID_CALLBACK_KEYS + typeof検証 | ingestion-engine.ts |

### C. パイプライン内部攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| C-01 | Hash chain tampering | ログフィールド改竄 → チェーン破壊検知回避 | **対策済**: SHA-256 + timingSafeEqual + deterministicStringify | integrity-signer.ts |
| C-02 | Hash chain replay | 過去の正当なハッシュ値を再利用 | **対策済**: previousHash連鎖で順序保証 | integrity-signer.ts |
| C-03 | Task priority manipulation | severity/executionLevel偽装 → 不正なタスク優先度 | **対策済**: ホワイトリスト検証 + deepFreeze | config-validator.ts |
| C-04 | PII masking bypass (circular ref) | 循環参照で再帰マスキング回避 | **対策済**: WeakSet + maxDepth | masking-service.ts |
| C-05 | Post-shutdown exploitation | stale referenceでshutdown後にパイプライン利用 | **対策済**: isShutdownガード on ingest/onTaskAction/updateCallbacks | index.ts |

### D. Transport層攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| D-01 | MITM on gRPC | 通信傍受 → ログ/PII漏洩 | **設定可能**: TLS cert/key in sentinel.yaml | config/sentinel.yaml |
| D-02 | Transport timeout manipulation | 極小timeout設定 → 全リモート送信失敗 | **対策済**: sendWithTimeout() + Promise.race + SentinelError。CircuitBreakerで連続失敗時の自動遮断も追加（RES-01, R-4） | index.ts, circuit-breaker.ts |
| D-03 | Dual-mode race condition | 並行ingestでlastProcessedLog上書き | **安全**: handle()は戻り値にlocalResultを使用、getLastProcessedLog()は防御コピー | ingestion-engine.ts |

### E. サプライチェーン攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| E-01 | 依存パッケージ脆弱性 (libpng型) | devDepsの脆弱性がビルド成果物に混入 | **対策済**: ランタイム依存ゼロ + npm audit 0件 | package.json |
| E-02 | バンドルコード改竄 | npm publishしたパッケージの改竄 | **.npmignore**: src/tests/docs除外。将来: npm provenance | .npmignore |
| E-03 | ビルドパイプライン攻撃 | rollupプラグイン経由のコード注入 | **低リスク**: rollup + typescript プラグインのみ。devDeps脆弱性0件 | rollup.config.js |
| E-04 | Transitive dependency exploit | 直接依存のdep tree内の脆弱性 | **対策済**: ランタイム依存ゼロ = transitive riskゼロ | — |

### F. サーバサイド攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| F-01 | gRPC API abuse | 大量リクエスト → サーバDoS | **対策済**: rate_limit_rps + rate_limit_burst | sentinel.yaml |
| F-02 | Auth bypass | API key偽装 → 不正アクセス | **対策済**: AuthUnaryInterceptor + HMAC検証 | grpc/interceptors.go |
| F-03 | RBAC escalation | viewer権限でadmin操作 | **対策済**: RBACAuthorizer | middleware/authorizer.go |
| F-04 | SQLite injection | 永続化クエリ注入 | **対策済**: パラメータバインド | store/ |
| F-05 | Notification provider abuse | Slack/Discord webhook偽装 | **対策済**: webhook HMAC署名 + ValidateWebhookURL（HTTPS必須、プライベートIP/localhost/リンクローカル拒否）。main.goでValidated constructors使用 | notify/url_validation.go |

### G. 運用・監査攻撃

| ID | 脅威 | 攻撃ベクトル | 現状 | 対策 |
|----|------|-------------|------|------|
| G-01 | ログ改竄 | DBログ直接書き換え → 監査証跡破壊 | **対策済**: hash chain検証で改竄検知 | integrity-signer.ts |
| G-02 | エラー情報漏洩 | エラーメッセージにPII含有 → ログ/Sentry漏洩 | **対策済**: maskPiiContext + serializeForAudit | error-utils.ts |
| G-03 | Sentinel.reset() abuse | 本番でreset() → セキュリティ設定消失 | **対策済**: 非test/local環境で警告 | index.ts |
