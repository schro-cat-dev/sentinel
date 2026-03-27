# Sentinel Architecture

## System Overview

Sentinel is split into two components that can operate independently or together.

```
                    ┌─────────────────────────────────┐
                    │    TypeScript Client SDK         │
                    │    (@sentinel/client)            │
                    │                                  │
                    │  Can run full pipeline locally   │
                    │  OR send logs to Go server       │
                    └──────────────┬──────────────────┘
                                   │ gRPC (Protocol Buffers)
                    ┌──────────────▼──────────────────┐
                    │    Go Backend Server             │
                    │    (sentinel-server)             │
                    │                                  │
                    │  Authoritative pipeline          │
                    │  HMAC-SHA256 integrity           │
                    │  Goroutine-safe concurrency      │
                    └─────────────────────────────────┘
```

---

## Design Principles

| Principle | How Applied |
|-----------|-------------|
| **Single Responsibility** | Each module has exactly one reason to change. Normalizer validates. Masking redacts. Detector detects. Generator generates. Executor dispatches. |
| **Open-Closed** | EventDetector uses `DetectionRule` interface. New detection rules = new struct, zero changes to existing code. |
| **Dependency Inversion** | Pipeline depends on interfaces (`ILogNormalizer`, `DetectionRule`, `TaskHandler`), not concrete implementations. |
| **Fail-Safe Defaults** | Hash chain enabled by default. HMAC key required at startup. KILL_SWITCH actions fail if no handler registered. |
| **Zero Trust Input** | Every field validated. UTF-8 checked. Null bytes rejected. Control characters removed. Invalid types fall back to safe defaults. |

---

## TypeScript Client SDK - Module Map

### Pipeline Flow

```
Sentinel.ingest(partialLog)
  │
  ▼
LogNormalizer.normalize()          src/core/engine/log-normalizer.ts
  │  Validates message (empty, length, type, level)
  │  Generates traceId if missing
  │  Sets defaults (serviceId, timestamp, boundary)
  ▼
MaskingService.mask()              src/security/masking-service.ts
  │  REGEX pattern matching
  │  PII_TYPE detection (email, credit card, phone, government ID)
  │  KEY_MATCH for sensitive object keys
  │  Circular reference protection (WeakSet)
  │  Configurable depth limit (default 10)
  ▼
IntegritySigner.calculateHash()    src/security/integrity-signer.ts
  │  SHA-256 deterministic serialization
  │  Keys sorted alphabetically
  │  hash/signature fields excluded from input
  │  previousHash chaining (in-memory)
  ▼
EventDetector.detect()             src/core/detection/event-detector.ts
  │  AI_AGENT origin logs skipped (loop prevention)
  │  Priority order: isCritical > SECURITY > COMPLIANCE > SLA
  │  Returns: eventName + priority + typed payload
  ▼
TaskGenerator.generate()           src/core/task/task-generator.ts
  │  Event name → rule index lookup
  │  Severity classification (log context + event type)
  │  Severity threshold filtering (rule.severity <= actual)
  │  Priority sorting (ascending)
  ▼
TaskExecutor.dispatch()            src/core/task/task-executor.ts
  │  Guardrail check: requireHumanApproval → blocked
  │  Execution level: AUTO → dispatch, MANUAL → block, MONITOR → skip
  │  Handler invocation by actionType
  │  Default handler fallback
  ▼
IngestionResult returned
```

### Module Responsibilities

| File | Responsibility | Inputs | Outputs |
|------|---------------|--------|---------|
| `src/index.ts` | Public API. Singleton. Wires all components. | `SentinelConfig` | `Sentinel` instance |
| `src/core/engine/ingestion-engine.ts` | Pipeline orchestration. No business logic. | `Partial<Log>` | `IngestionResult` |
| `src/core/engine/log-normalizer.ts` | Validation + default injection | `Partial<Log>` | `Log` (complete) |
| `src/security/masking-service.ts` | PII redaction across all field types | `data`, `rules`, `preserveFields` | Masked data |
| `src/security/integrity-signer.ts` | Hash chain state + hash computation | `Log`, `previousHash` | SHA-256 hex string |
| `src/core/detection/event-detector.ts` | Pattern-based event detection | `Log` | `DetectionResult` or null |
| `src/core/task/severity-classifier.ts` | Map event + log context to severity | `DetectionResult`, `Log` | `TaskSeverity` |
| `src/core/task/task-generator.ts` | Rule matching + task creation | `DetectionResult`, `Log` | `GeneratedTask[]` |
| `src/core/task/task-executor.ts` | Guardrail enforcement + handler dispatch | `GeneratedTask` | `TaskResult` |

### Shared Layer (not in pipeline, available for reuse)

| File | Responsibility |
|------|---------------|
| `src/shared/functional/result.ts` | `Result<T, E>` monad with map, flatMap, match, safe (async retry), guard, all |
| `src/shared/constants/kinds/` | Error taxonomy: 6 application categories (auth, validation, permission, access, security, limit-over) + 4 persistence categories (db, cache, datastore, storage) |
| `src/shared/constants/error-layer.ts` | 50+ system layer classifications for error traceability |
| `src/shared/utils/error-utils.ts` | PII-safe error serialization, severity classification, i18n error messages |

### Type Definitions

| File | Key Types |
|------|-----------|
| `src/types/log.ts` | `Log`, `LogType` (7 types), `LogLevel` (1-6), `LogTag`, `Origin`, `AIAgentEventBacklog` |
| `src/types/task.ts` | `TaskRule`, `GeneratedTask`, `TaskResult`, `TaskActionType` (6 actions), `TaskSeverity` (5 levels), `TaskExecutionLevel` (4 levels) |
| `src/types/event.ts` | `SystemEventMap` (4 events with typed payloads), `DetectionResult<K>`, `WorkerToMainMessage` |

---

## Go Backend Server - Module Map

### Pipeline Flow

```
gRPC IngestRequest (protobuf)
  │
  ▼
protoToLog()                       internal/grpc/server.go
  │  Proto message → domain.Log conversion
  ▼
LogNormalizer.Normalize()          internal/engine/normalizer.go
  │  UTF-8 validation
  │  Null byte rejection
  │  Control character removal
  │  Message length check (max 65536)
  │  UUID generation for traceId
  │  Type/level/origin validation with safe defaults
  ▼
MaskingService.MaskLog()           internal/security/masking.go
  │  Masks log.Message (REGEX + PII_TYPE rules)
  │  Masks log.ActorID (unless preserved)
  │  Masks log.Tags[].Category (unless key preserved)
  ▼
IntegritySigner.ApplyHashChain()   internal/security/signer.go
  │  Atomic: mutex lock → read previousHash → compute HMAC-SHA256 → update chain → unlock
  │  Deterministic JSON: keys sorted, hash/signature excluded
  │  Constant-time verification (crypto/subtle)
  ▼
EventDetector.Detect()             internal/detection/detector.go
  │  Iterates DetectionRule interface implementations
  │  AI_AGENT origin skipped (unless isCritical)
  │  Returns first match (priority order)
  ▼
TaskGenerator.Generate()           internal/task/generator.go
  │  Event name → rule index
  │  Severity classification (same logic as TS SDK)
  │  Severity threshold + priority sort
  ▼
TaskExecutor.Dispatch()            internal/task/executor.go
  │  Guardrails: requireHumanApproval → blocked_approval
  │  MANUAL → blocked_approval, MONITOR → skipped
  │  KILL_SWITCH/AUTOMATED_REMEDIATE without handler → error (fail-safe)
  │  RWMutex-protected handler registry
  ▼
IngestResponse (protobuf)
```

### Module Responsibilities

| Package | Key Files | Responsibility |
|---------|-----------|---------------|
| `internal/domain` | log.go, task.go, event.go, result.go | Domain models with validation methods. No external dependencies. |
| `internal/engine` | pipeline.go, normalizer.go, agent_bridge.go, routing.go | 10-stage pipeline orchestration. Input validation. Agent delegation. Approval routing. |
| `internal/security` | signer.go, masking.go, masking_jp.go, masking_policy.go, masking_verify.go, sanitizer.go | HMAC-SHA256 hash chain (key rotation). PII masking (regex + category + Japan-specific). Policy engine. Post-mask verification. ReDoS prevention. |
| `internal/detection` | detector.go, ensemble.go, rules.go, dynamic_rule.go, anomaly.go, dedup.go | Ensemble detection (all rules + score aggregation). Dynamic YAML rules. Statistical anomaly detection. Deduplication. |
| `internal/response` | orchestrator.go, strategy.go, block_agent.go, block_provider.go, analysis_agent.go | Threat response orchestration (5 strategies). Block dispatch (IP/Account/AWS/GCP/Azure). Approval-gated blocking. AI analysis. |
| `internal/notify` | notifier.go, adapters.go | Multi-channel notification (Slack/Gmail/Discord/Webhook/Log). Prefix-based routing. Retry support. |
| `internal/middleware` | auth.go, authorizer.go, security_config.go | API key auth. RBAC authorization. Rate limiting. Security headers. Audit logging. |
| `internal/task` | generator.go, executor.go | Rule-indexed task generation. Handler registry with RWMutex. Fail-safe for critical actions. |
| `internal/agent` | provider.go, executor.go, mock_provider.go | AI provider interface. Loop-depth tracking. Timeout enforcement. Result re-ingestion. |
| `internal/store` | store.go, sqlite.go, factory.go | Store interface. SQLite (WAL) + SQLCipher (AES-256-CBC). Driver factory. |
| `internal/retry` | retry.go | Exponential backoff + full jitter. Generic `DoWithResult[T]`. |
| `internal/grpc` | server.go, interceptors.go | gRPC service (Ingest/HealthCheck/Tasks/Approval/Block). Auth + rate limit interceptors. Audit log interceptor. |
| `internal/webhook` | notifier.go | Approval notification via webhook (HMAC-signed). |
| `config` | config.go | YAML config loading + env var overrides + validation + defaults. |
| `cmd/server` | main.go | Entry point. Full module wiring. TLS support. Structured logging (slog/JSON). Graceful shutdown. |

### Detection Rules (Strategy Pattern)

| Rule | Trigger | Event Generated | Priority |
|------|---------|----------------|----------|
| `CriticalRule` | `log.IsCritical == true` | `SYSTEM_CRITICAL_FAILURE` | HIGH |
| `SecurityIntrusionRule` | `type == SECURITY && level >= 5` | `SECURITY_INTRUSION_DETECTED` | HIGH |
| `ComplianceViolationRule` | `type == COMPLIANCE && message contains "violation"` | `COMPLIANCE_VIOLATION` | HIGH |
| `SLAViolationRule` | `type == SLA && level >= 4` | `SYSTEM_CRITICAL_FAILURE` | MEDIUM |

Adding a new rule:
1. Define payload struct in `internal/domain/event.go` implementing `EventPayload`
2. Create rule struct in `internal/detection/rules.go` implementing `DetectionRule`
3. Register in `NewEventDetector()` or inject via `NewEventDetectorWithRules()`

### Concurrency Model

| Component | Mechanism | Scope |
|-----------|-----------|-------|
| `IntegritySigner` | `sync.Mutex` | Hash chain read/compute/update is atomic |
| `TaskExecutor` | `sync.RWMutex` | Handler registration (write) vs dispatch (read) |
| `Pipeline` | Stateless except signer | Each gRPC call processes independently |
| gRPC server | goroutine-per-request | Standard gRPC concurrency model |

Verified with `go test -race` (682 tests across 13 packages, 0 data races).

---

## Dependency Map

### TypeScript SDK

```
index.ts (Sentinel)
  ├── configs/sentinel-config.ts
  ├── configs/masking-rule.ts
  ├── core/engine/ingestion-engine.ts
  │     ├── core/engine/log-normalizer.ts
  │     ├── security/masking-service.ts
  │     ├── security/integrity-signer.ts
  │     ├── core/detection/event-detector.ts
  │     ├── core/task/task-generator.ts
  │     │     └── core/task/severity-classifier.ts
  │     └── core/task/task-executor.ts
  └── types/ (log.ts, task.ts, event.ts)

External dependencies: NONE (zero npm dependencies)
Node.js built-in only: node:crypto (SHA-256)
```

### Go Server

```
cmd/server/main.go
  ├── config/config.go                    (YAML + env overrides)
  ├── internal/grpc/server.go             (gRPC service + interceptors)
  │     └── internal/engine/pipeline.go   (10-stage pipeline)
  │           ├── internal/engine/normalizer.go
  │           ├── internal/middleware/authorizer.go   (RBAC)
  │           ├── internal/security/masking.go        (+ policy + verify + JP)
  │           ├── internal/security/signer.go         (+ key rotation)
  │           ├── internal/detection/ensemble.go      (+ dynamic_rule + anomaly + dedup)
  │           ├── internal/response/orchestrator.go   (+ block + analysis + notify)
  │           ├── internal/task/generator.go
  │           ├── internal/task/executor.go
  │           └── internal/engine/agent_bridge.go     (→ agent/executor)
  ├── internal/store/factory.go           (sqlite / sqlite_encrypted)
  ├── internal/notify/notifier.go         (Slack/Gmail/Discord/Webhook)
  ├── internal/retry/retry.go             (exponential backoff + jitter)
  └── internal/domain/                    (all domain models)

External dependencies:
  - google.golang.org/grpc (gRPC framework)
  - google.golang.org/protobuf (Protocol Buffers)
  - github.com/google/uuid (UUID generation)
  - github.com/nicholasgasior/gocipher (SQLCipher, optional)
```
