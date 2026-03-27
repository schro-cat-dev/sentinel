# Sentinel

**Intelligent Log-to-Task Automation Platform**

Sentinel detects events from application logs and automatically generates remediation tasks based on configurable rules. The core value is converting logs into actionable tasks — not just collecting them.

The system consists of a **TypeScript client SDK** (`@sentinel/client`) and a **Go backend server** communicating over gRPC.

[Architecture](docs/architecture.md) | [Security](docs/security.md) | [Usage Guide](docs/usage-guide.md) | [日本語](readme/ja.md)

---

## Project Status: **v1 MVP**

| Component | Technology | Status | Tests |
|-----------|-----------|--------|-------|
| Client SDK | TypeScript (zero dependencies) | Implemented | 177 tests (Vitest) |
| Backend Server | Go 1.26 + gRPC | Implemented | 134 tests (`-race` verified) |
| gRPC Communication | Protocol Buffers v3 | Implemented | End-to-end verified |

---

## What Sentinel Does

```
Application log arrives
    -> Normalize (validate, defaults, trim)
    -> Mask PII (email, phone, credit card, government ID)
    -> Hash-chain (HMAC-SHA256, tamper detection)
    -> Detect event (critical failure, security intrusion, compliance violation, SLA breach)
    -> Generate task (rule-based, severity-filtered, priority-sorted)
    -> Dispatch action (AUTO / SEMI_AUTO / MANUAL / MONITOR)
```

A critical database failure log triggers a `SYSTEM_NOTIFICATION` task automatically dispatched to registered handlers. A security intrusion triggers an `AI_ANALYZE` task. A compliance violation triggers an `ESCALATE` task requiring human approval.

---

## Architecture

```
┌──────────────────┐       gRPC        ┌──────────────────────┐
│  Applications    │  ──────────────>  │  Go Sentinel Server  │
│  (@sentinel/     │                   │                      │
│   client SDK)    │  <──────────────  │  Normalize           │
│                  │   IngestResponse   │  Mask PII            │
│  TypeScript      │                   │  Hash-chain (HMAC)   │
│  Zero deps       │                   │  Detect events       │
│  ESM + CJS       │                   │  Generate tasks      │
└──────────────────┘                   │  Dispatch actions    │
                                       └──────────────────────┘
```

The TS client SDK can also run the full pipeline locally (without the Go server) for development and testing. See [Usage Guide](docs/usage-guide.md) for details.

---

## Quick Start

### Go Server

```bash
cd packages/server

# Required: set HMAC key (minimum 32 bytes)
export SENTINEL_HMAC_KEY="your-secret-key-at-least-32-bytes-long"

# Build and run
go build -o sentinel-server ./cmd/server/
./sentinel-server
# Output: {"level":"INFO","msg":"server listening","addr":":50051"}

# Test with grpcurl
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  -d '{"message":"DB pool exhausted","type":"SYSTEM","level":6,"is_critical":true}' \
  localhost:50051 sentinel.v1.SentinelService/Ingest
```

### TypeScript Client SDK

```typescript
import { Sentinel, createDefaultConfig } from "@schro-cat-dev/sentinel";

const sentinel = Sentinel.initialize(createDefaultConfig({
  projectName: "my-app",
  serviceId: "payment-service",
  security: { enableHashChain: true },
  masking: {
    enabled: true,
    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
    preserveFields: ["traceId"],
  },
  taskRules: [{
    ruleId: "crit-notify",
    eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "HIGH",
    actionType: "SYSTEM_NOTIFICATION",
    executionLevel: "AUTO",
    priority: 1,
    description: "Notify on critical failure",
    executionParams: { notificationChannel: "#incidents" },
    guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
  }],
}));

sentinel.onTaskAction("SYSTEM_NOTIFICATION", (task) => {
  console.log(`Task dispatched: ${task.taskId} (${task.severity})`);
});

const result = await sentinel.ingest({
  message: "Database connection pool exhausted",
  isCritical: true,
  level: 6,
  boundary: "db-service:pool",
});
// result.tasksGenerated[0].status === "dispatched"
```

---

## Project Structure

```
sentinel/
├── src/                          # TypeScript Client SDK
│   ├── index.ts                  # Public API (Sentinel class)
│   ├── configs/                  # Configuration types
│   ├── core/
│   │   ├── engine/               # Ingestion pipeline
│   │   ├── detection/            # Event detection rules
│   │   └── task/                 # Task generation + execution
│   ├── security/                 # Hash-chain, PII masking
│   ├── shared/                   # Error taxonomy, Result monad, utilities
│   └── types/                    # Domain models (Log, Task, Event)
├── tests/                        # TS tests (177 cases)
├── packages/
│   └── server/                   # Go Backend Server
│       ├── cmd/server/           # Entry point
│       ├── internal/
│       │   ├── domain/           # Domain models
│       │   ├── engine/           # Pipeline + normalizer
│       │   ├── detection/        # Rule-based detection (Strategy pattern)
│       │   ├── security/         # HMAC-SHA256 signer, PII masking
│       │   ├── task/             # Task generator + executor
│       │   └── grpc/             # gRPC server implementation
│       ├── proto/                # Protocol Buffers definition
│       └── testutil/             # Test fixtures
└── docs/                         # Documentation
```

---

## Testing

```bash
# TypeScript SDK (177 tests)
npm test

# Go Server (134 tests with race detector)
cd packages/server
go test ./... -race -count=1

# Go Server with verbose output
go test ./... -race -v -count=1
```

---

## Documentation

| Document | Content |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | Module responsibilities, design principles, dependency map |
| [docs/security.md](docs/security.md) | HMAC, PII masking, TLS, audit trail, threat model |
| [docs/usage-guide.md](docs/usage-guide.md) | Setup, configuration reference, API examples |

---

## License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
