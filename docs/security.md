# Sentinel Security Design

## Threat Model

Sentinel processes application logs that may contain PII, security events, and compliance-critical data. The threat model addresses:

| Threat | Mitigation | Status |
|--------|-----------|--------|
| **Log tampering** | Hash chain — SDK: SHA-256 (keyless, local integrity), Server: HMAC-SHA256 (keyed, tamper proof) | Implemented |
| **PII exposure in logs** | Multi-pattern masking (regex, category, key-match) | Implemented |
| **Timing attacks on hash verification** | `crypto/subtle.ConstantTimeCompare` (Go), `crypto.timingSafeEqual` (TS SDK) | Implemented |
| **Replay attacks** | Hash chain links each log to its predecessor | Implemented |
| **Log injection (null bytes, control chars)** | Input validation rejects invalid UTF-8, null bytes; strips control characters | Implemented |
| **Unauthorized log submission** | gRPC with payload size limits (1MB) | Implemented (size limits) |
| **Secret key exposure** | Environment variable required, no defaults, minimum 32 bytes | Implemented |
| **Concurrent state corruption** | `sync.Mutex` on hash chain (Go), async mutex on `IngestionEngine.handle()` (TS SDK), `sync.RWMutex` on handler registry | Implemented |
| **PII in error messages** | gRPC returns generic error codes; details logged server-side only | Implemented |
| **Critical action without handler** | `KILL_SWITCH` / `AUTOMATED_REMEDIATE` fail if no handler registered | Implemented |
| **MitM on gRPC** | TLS support (`server.tls_cert_file` / `server.tls_key_file`) | Implemented |
| **Service impersonation** | API key authentication (gRPC metadata interceptor) | Implemented |
| **Rate-based DoS** | Per-client rate limiting | Implemented (gRPC interceptor) |
| **Transient failure** | Exponential backoff + jitter retry (`internal/retry/`) | Implemented |
| **Partial DB write** | `store.WithTx()` for atomic multi-step operations | Implemented |
| **Invalid SDK input** | Runtime validator at `ingest()` boundary | Implemented |
| **RBAC bypass** | Per-client log type/level authorization | Implemented |
| **Threat auto-response** | Strategy-based block/analyze/notify orchestration | Implemented |

---

## Hash Chain Integrity

### Algorithm

**Go Server (keyed HMAC):**
```
H_n = HMAC-SHA256(key, serialize(L_n) + H_{n-1})

Where:
  key      = SENTINEL_HMAC_KEY (minimum 32 bytes, from environment variable)
  L_n      = Log entry with hash and signature fields zeroed
  H_{n-1}  = Previous log's hash (empty string for first log)
  serialize = Deterministic JSON (keys sorted alphabetically at every depth)
```

**TypeScript SDK (keyless SHA-256):**
```
H_n = SHA-256(serialize(L_n) + H_{n-1})

SDK uses keyless SHA-256 for local integrity verification.
For authenticated tamper detection, use remote/dual mode with the Go Server.
```

### Properties

| Property | Guarantee |
|----------|-----------|
| **Integrity** | Any modification to a log entry invalidates its hash and all subsequent hashes |
| **Ordering** | Each hash depends on the previous, enforcing sequential order |
| **Authenticity** | HMAC requires the secret key; without it, valid hashes cannot be forged |
| **Determinism** | Same log + same previousHash + same key = same hash (keys sorted, undefined → null) |
| **Constant-time verification** | Go uses `crypto/subtle.ConstantTimeCompare`, TS SDK uses `crypto.timingSafeEqual` |

### What is NOT guaranteed

| Limitation | Reason |
|-----------|--------|
| Cross-server chain | Each server instance maintains its own in-memory chain. Chain resets on restart. |
| Non-repudiation | HMAC is symmetric. Both parties with the key can produce valid hashes. Use Ed25519 signatures for non-repudiation (not implemented). |
| Persistence | Hash chain lives in memory only. For durable chains, persist hashes to external storage. |

### Key Management

```bash
# Generate a secure key
openssl rand -base64 32

# Set as environment variable (required)
export SENTINEL_HMAC_KEY="$(openssl rand -base64 32)"

# The server refuses to start without a valid key
# Minimum length: 32 bytes
```

The Go server validates the key at startup:
- Empty key: exits with error
- Key < 32 bytes: exits with error
- No hardcoded defaults exist in the codebase

---

## PII Masking

### Covered PII Patterns

| Category | Pattern | Example Input | Masked Output |
|----------|---------|---------------|---------------|
| `EMAIL` | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | `admin@example.com` | `[MASKED_EMAIL]` |
| `CREDIT_CARD` | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b` | `4111 1111 1111 1111` | `[MASKED_CREDIT_CARD]` |
| `PHONE` | `(\+81\|0)[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{4}` | `090-1234-5678`, `+81-90-1234-5678` | `[MASKED_PHONE]` |
| `GOVERNMENT_ID` | `\b\d{12}\b` | `123456789012` | `[MASKED_GOVERNMENT_ID]` |

### Masking Scope

**Go Server** masks the following fields:
- `log.Message` — always masked
- `log.ActorID` — masked unless `"actorId"` is in `preserveFields`
- `log.Tags[].Category` — masked unless the tag's `Key` is in `preserveFields`

**TypeScript SDK** masks (v2 hardened):
- `log` object 全体を再帰的にマスク — message, input, details, tags 含む全フィールド
- String fields via `REGEX`, `PII_TYPE` rules
- Object keys via `KEY_MATCH` rules (case-insensitive)
- `normalizeOnly()` (remote/dual mode transport送信用) もマスキング適用済み

### Rule Types

| Type | Description | Configuration |
|------|-------------|---------------|
| `REGEX` | Custom regex pattern with replacement string | `{ type: "REGEX", pattern: /secret-\d+/, replacement: "[REDACTED]" }` |
| `PII_TYPE` | Built-in PII category detection | `{ type: "PII_TYPE", category: "EMAIL" }` |
| `KEY_MATCH` | Mask object keys by name | `{ type: "KEY_MATCH", sensitiveKeys: ["password", "ssn"] }` |

### Preserve Fields

Fields listed in `preserveFields` are exempt from masking. Use this for correlation IDs that must remain readable:

```typescript
preserveFields: ["traceId", "spanId"]
```

### Known Limitations

| Limitation | Detail |
|-----------|--------|
| Phone patterns | Japan-format (+81/0XX) supported. Other international formats not covered. |
| Credit card validation | Pattern-based only. No Luhn algorithm check. |
| Unicode normalization | Different Unicode representations of the same character may bypass regex. |
| Custom REGEX safety | User-provided `REGEX` patterns are validated at config load time: pattern length limit (256), nested quantifier detection (`detectReDoSRisk`), and runtime input length guard (65536). See `config-loader.ts` and `masking-service.ts`. |

---

## Input Validation (Go Server)

The normalizer (`internal/engine/normalizer.go`) enforces:

| Check | Behavior |
|-------|----------|
| Empty message | Returns error (rejected) |
| Message > 65,536 chars | Returns error (rejected) |
| Invalid UTF-8 | Returns error (rejected) |
| Null bytes (`\x00`) | Returns error (rejected) |
| Control characters | Silently removed (except `\t` and `\n`) |
| Invalid LogType | Falls back to `SYSTEM` |
| Invalid LogLevel (outside 1-6) | Falls back to `3` (INFO) |
| Invalid Origin | Falls back to `SYSTEM` |
| Missing traceId | Auto-generated UUID v4 |
| Missing timestamp | Set to `time.Now().UTC()` |
| Missing boundary | Set to `"unknown"` |

---

## gRPC Security

### Current Implementation

| Feature | Status |
|---------|--------|
| Payload size limit | 1MB (MaxRecvMsgSize / MaxSendMsgSize) |
| Concurrent stream limit | 1000 (MaxConcurrentStreams) |
| Error message sanitization | Internal errors return `codes.Internal` with generic message |
| Input validation at API boundary | Empty message returns `codes.InvalidArgument` |
| Structured logging | `log/slog` JSON format with traceId |
| Graceful shutdown | 30-second timeout, then force stop |

### Implemented Security Features

| Feature | Status | Configuration |
|---------|--------|---------------|
| TLS (server-side) | Implemented | `server.tls_cert_file` / `server.tls_key_file` in config YAML |
| API key authentication | Implemented | `auth.enabled: true` + `auth.api_keys` or `SENTINEL_API_KEYS` env var |
| Per-client rate limiting | Implemented | `auth.rate_limit_rps` / `auth.rate_limit_burst` (gRPC interceptor) |
| RBAC authorization | Implemented | `authorization.enabled: true` with role definitions |
| Audit logging | Implemented | `AuditLogUnaryInterceptor` records all gRPC requests |
| Data encryption at rest | Implemented | `store.driver: sqlite_encrypted` + `SENTINEL_STORE_ENCRYPTION_KEY` |

### Not Yet Implemented (Production Roadmap)

| Feature | Priority | Notes |
|---------|---------|-------|
| mTLS (mutual) | Recommended | Client certificate verification against CA pool |
| Request tracing | Recommended | OpenTelemetry gRPC interceptor |

---

## Task Execution Safety

### Execution Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| `AUTO` | Dispatched immediately to registered handlers | Low-risk automated responses (notifications, logging) |
| `SEMI_AUTO` | Dispatched unless `requireHumanApproval` is set | Medium-risk actions (restart services, adjust configs) |
| `MANUAL` | Always blocked (requires human approval) | High-risk actions (data deletion, infrastructure changes) |
| `MONITOR` | Skipped (no action taken, observation only) | Baseline monitoring, trend analysis |

### Guardrails

| Guardrail | Effect |
|-----------|--------|
| `requireHumanApproval: true` | Task status set to `blocked_approval` regardless of execution level |
| No handler registered for `KILL_SWITCH` | Returns error (Go server). Task marked as `failed`. |
| No handler registered for `AUTOMATED_REMEDIATE` | Returns error (Go server). Task marked as `failed`. |
| No handler registered for other actions | Task marked as `dispatched` (noop). |

### AI Loop Prevention

Logs with `origin: "AI_AGENT"` are not evaluated by the EventDetector (unless `isCritical: true`). This prevents:
1. AI agent generates a log
2. Detector fires on that log
3. Task generated triggers AI agent
4. AI agent generates another log → infinite loop

---

## Audit Trail

Every processed log produces an `IngestionResult` containing:

```json
{
  "traceId": "uuid-v4",
  "hashChainValid": true,
  "masked": true,
  "tasksGenerated": [
    {
      "taskId": "uuid-v4",
      "ruleId": "crit-notify",
      "status": "dispatched",
      "dispatchedAt": "2026-01-01T00:00:00Z"
    }
  ]
}
```

Server-side structured logs (JSON via `log/slog`) include:
- `traceId` for correlation
- Error details (server-side only, never sent to client)
- Task dispatch events with ruleId, actionType, severity

---

## Validation Boundaries

入力検証は SDK と Server の**2箇所**で行われる。各レイヤーの責務は明確に分離されている。

| 検証項目 | SDK (TypeScript) | Server (Go) |
|---|---|---|
| message 必須 | `log-validator.ts`: 必須/空/null byte/65536超 | `normalizer.go`: 空/null byte/UTF-8/65536超 |
| message サニタイズ | なし（そのまま渡す） | `sanitizer.go`: 制御文字除去 |
| type ホワイトリスト | `log-validator.ts`: 7種チェック | `sanitizer.go`: `allowedLogTypes` |
| level 範囲 | `log-validator.ts`: 1-6整数 | `log.go`: `IsValidLogLevel` |
| origin ホワイトリスト | `log-validator.ts`: SYSTEM/AI_AGENT | `sanitizer.go`: `allowedOrigins` |
| tags 数/長さ | `log-validator.ts`: 100件/key128/value1024 | `normalizer.go`: 100件上限 |
| resourceIds 数 | `log-validator.ts`: 100件 | `normalizer.go`: 100件上限 |
| PII マスキング | `MaskingService` | `MaskingService` + `MaskingPolicyEngine` + `MaskingVerifier` |
| ReDoS 防止 | `detectReDoSRisk` (パターン長256 + ネスト量指定子検出) + 入力長ガード (65536) | `sanitizer.go`: `ValidateRegexSafety` |
| RBAC 認可 | なし（SDKはクライアント側） | `authorizer.go`: ロール→権限 |

| actorId/traceId/spanId/boundary/traceInfo | `log-validator.ts`: maxStringFieldLength (default 512) | サーバ側でも同様の制限 |
| resourceIds 各要素 | `log-validator.ts`: maxResourceIdLength (default 512) | — |
| input JSONサイズ | `log-validator.ts`: maxInputSize (default 1MB) | `normalizer.go`: サイズ制限 |
| total logサイズ | `log-validator.ts`: maxTotalLogSize (default 2MB) | `normalizer.go`: サイズ制限 |

**設計原則**: SDK は「明らかに不正な入力を早期に弾く」（validateLogInput）。LogNormalizer は「防御的フォールバック」のみ（検証は行わない）。Server は「全フィールドを厳密に検証・サニタイズする」。

---

## ValidationLimits (設定可能なサイズ制限)

SDK の `ValidationLimits` により、全フィールドのサイズ制限を設定時にカスタマイズ可能。デフォルト値はセキュリティとユーザビリティのバランスを考慮して設定。

```typescript
const config = createDefaultConfig({
  projectName: "my-project",
  serviceId: "svc-1",
  validationLimits: {
    maxMessageLength: 65536,
    maxStringFieldLength: 512,   // actorId, traceId, spanId, boundary, traceInfo
    maxResourceIdLength: 512,
    maxInputSize: 1_048_576,     // 1MB
    maxTotalLogSize: 2_097_152,  // 2MB
  },
});
```

| フィールド | デフォルト上限 | 超過時の動作 |
|-----------|-------------|------------|
| message | 65,536 chars | ValidationError |
| details | 65,536 chars | ValidationError |
| actorId/traceId/spanId/parentSpanId/boundary/traceInfo | 512 chars | ValidationError |
| tags | 100件、key 128 chars、category 1024 chars | ValidationError |
| resourceIds | 100件、各要素 512 chars | ValidationError |
| input (JSON概算) | 1,048,576 bytes (1MB) | ValidationError |
| ログ全体 (概算) | 2,097,152 bytes (2MB) | ValidationError |

---

## Retry & Resilience

HTTP通知・AI実行等の外部通信は一時障害で失敗しうる。`internal/retry/` パッケージで統一対応。

```
delay = random(0, min(maxDelay, baseDelay * multiplier^attempt))
```

| 対象 | リトライ | 設定 |
|---|---|---|
| 通知送信（Slack/Gmail/Discord/Webhook） | `MultiNotifier` 内で `retry.Do()` | MaxAttempts=3, BaseDelay=100ms, MaxDelay=5s |
| AI分析エージェント | `Guardrails.MaxRetries`（今後適用予定） | タスクルールで設定 |
| DB永続化 | リトライなし（SQLite WAL でほぼ失敗しない） | — |

**Jitter**: Full jitter（`random(0, backoff)`）で thundering herd を回避。

---

## Data Atomicity

`store.WithTx()` で多段DB操作を原子的に実行可能。

```go
store.WithTx(ctx, func(tx interface{}) error {
    // tx を使って複数操作
    // エラー時は自動ROLLBACK
    return nil
})
```

**注意**: 現在 Pipeline.Process() 内のDB操作は個別実行。クリティカルパス（ApproveTask等）で `WithTx` を使用することを推奨。

---

## Compliance Considerations

| Standard | Relevant Controls | Sentinel Coverage |
|----------|-------------------|-------------------|
| **SOC 2 Type II** | CC6.1 (logical access), CC7.2 (monitoring) | Hash chain integrity, PII masking, structured audit logging |
| **ISO 27001** | A.12.4 (logging), A.18.1.4 (privacy) | Tamper-evident logs, PII redaction, error taxonomy |
| **GDPR** | Art. 5(1)(f) (integrity), Art. 32 (security) | HMAC integrity, masking at collection point |
| **PCI DSS** | Req. 10 (logging), Req. 3 (protect stored data) | Credit card masking, hash chain, audit trail |

### Not Yet Addressed

| Requirement | Gap |
|-------------|-----|
| GDPR Right to Erasure (Art. 17) | No mechanism to find/delete logs by actor ID |
| SOC 2 CC6.3 (role-based access) | RBAC implemented (`middleware/authorizer.go`) |
| ISO 27001 A.10.1 (cryptographic controls policy) | Key rotation not automated |
| PCI DSS Req. 10.5 (secure audit trails) | Logs persisted to SQLite (WAL mode). Threat responses also persisted. |
