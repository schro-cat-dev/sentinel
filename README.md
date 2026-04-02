# Sentinel

**Detect threats in your logs. Automatically respond.**

[Architecture](docs/architecture.md) | [Security](docs/security.md) | [Usage Guide](docs/usage-guide.md) | [日本語](readme/ja.md)

---

## What It Does

Sentinel watches your application logs, detects security threats and system failures, and automatically triggers actions — blocking malicious IPs, notifying your team, or escalating to an AI analyst.

```
Your app logs: "Failed login from 203.0.113.45 (attempt #50 in 5 min)"
    |
    v
Sentinel detects: Brute force attack
    |
    v
Automatically: Block IP + Notify #security on Slack + Log for audit
```

The system has two components:
- **TypeScript SDK** — Zero-dependency client library. Works standalone or with the server.
- **Go Server** — Backend with persistence, RBAC, ensemble detection, and threat response.

---

## Quick Start

### Prerequisites

- **Node.js 20+** (SDK)
- **Go 1.22+** (Server, optional)

### Option A: SDK Only (Local Mode)

No server needed. Logs are processed entirely in your Node.js process.

```bash
npm install @schro-cat-dev/sentinel
```

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

// Handle generated tasks
sentinel.onTaskAction("SYSTEM_NOTIFICATION", async (task) => {
  console.log(`[${task.severity}] ${task.description}`);
});

// Ingest a log
const result = await sentinel.ingest({
  message: "Database connection pool exhausted",
  isCritical: true,
  level: 6,
  boundary: "db-service:pool",
});

console.log(result.detection?.eventName);  // "SYSTEM_CRITICAL_FAILURE"
console.log(result.tasksGenerated[0].status);  // "dispatched"

await sentinel.shutdown();
```

### Option B: With Go Server (Remote/Dual Mode)

Full-featured setup with persistence, threat response, and AI analysis.

```bash
# Terminal 1: Start server
cd packages/server
export SENTINEL_HMAC_KEY="$(openssl rand -base64 32)"
go build -o sentinel-server ./cmd/server/ && ./sentinel-server
# => Listening on :50051

# Terminal 2: SDK connects via gRPC (user provides transport implementation)
# See: docs/usage-guide.md#remote-mode
```

### Verify

```bash
# SDK tests
npm test
# => 2,933 tests passed

# Go server tests
cd packages/server && go test ./... -race -count=1
# => 786 tests passed
```

---

## How It Works

```
  SDK Pipeline (TypeScript — runs in your Node.js process)
  ─────────────────────────────────────────────────────────
    Validate       → Input validation (null bytes, size limits, surrogate pairs)
    Normalize      → Defaults, sanitize, monotonic clock
    Mask PII       → 8-category masking (email, phone, credit card, gov ID, etc.)
    Hash-chain     → SHA-256 integrity chain (constant-time comparison)
    Detect         → Rule-based event detection (built-in + custom rules)
    Generate Task  → Severity-filtered, priority-sorted task creation
    Dispatch       → AUTO / SEMI_AUTO / MANUAL / MONITOR execution

  Go Server Pipeline (additional stages in remote/dual mode)
  ─────────────────────────────────────────────────────────
    Authorization  → RBAC (per-client log type/level restrictions)
    Normalize      → Re-validate, UTF-8 enforcement
    Mask PII       → Policy-based masking + post-mask residual PII verification
    Hash-chain     → HMAC-SHA256 (keyed, with key rotation)
    Persist        → SQLite/SQLCipher with WAL
    Detect         → Ensemble detection (rules + dynamic rules + anomaly)
    Threat Response→ Block IP / Analyze with AI / Notify team
    Generate Task  → Server-side task generation + AI agent delegation
```

---

## Architecture

```
┌──────────────────┐                   ┌──────────────────────────────────┐
│  Applications    │     gRPC          │  Go Sentinel Server              │
│                  │  (user injects    │                                  │
│  @sentinel/      │   gRPC client     │  Auth → Authz → RateLimit        │
│  client SDK      │   via Transport   │  Normalize → Mask(Policy)        │
│                  │   interface)      │  Verify → HashChain → Persist    │
│  TypeScript      │  ──────────────>  │  Detect(Ensemble + Anomaly)      │
│  Zero deps       │  <──────────────  │  ThreatResponse(Block/Analyze)   │
│  ESM + CJS       │                   │  TaskGenerate → AgentBridge      │
│                  │                   └──────────────────────────────────┘
│  Works standalone│                                  │
│  (local mode)    │                   ┌──────────────┴──────────────┐
└──────────────────┘                   │                             │
                                  ┌────▼────┐                 ┌─────▼─────┐
                                  │ Notify  │                 │ AI Agent  │
                                  │ (I/F)   │                 │ (Mock)    │
                                  │ Slack   │                 │ Analyze   │
                                  │ Gmail   │                 │ Block IP  │
                                  │ Discord │                 │ Lock Acct │
                                  │ Webhook │                 │ AWS/GCP/  │
                                  └─────────┘                 │ Azure(I/F)│
                                                              └───────────┘
Note: Notification, AI analysis, and cloud blocking are currently Mock/Interface
implementations. Users inject their own adapters for real providers.
```

---

## Threat Response Strategies (Go Server)

| Strategy | Behavior |
|---|---|
| `BLOCK_AND_NOTIFY` | Analyze with AI -> Block IP/Account -> Notify with results |
| `ANALYZE_AND_NOTIFY` | Analyze with AI -> Notify with analysis (no block) |
| `NOTIFY_ONLY` | Notify detection result only |
| `BLOCK_ONLY` | Block immediately (silent defense) |
| `MONITOR` | Log only (no action) |

---

## Documentation

### Getting Started

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/usage-guide.md) | Configuration, API reference, all options |
| [YAML Config Template](sentinel.config.yaml.example) | SDK用 YAML 設定テンプレート（環境変数展開対応） |
| [Docker Deployment](packages/server/docs/docker-guide.md) | Dockerfile, docker-compose, Kubernetes |
| [Migration v1 to v2](docs/migration-v1-to-v2.md) | Upgrade steps, no breaking changes |

### Architecture & Security

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | SDK + Server pipeline flow, module responsibility map |
| [Security Design](docs/security.md) | Threat model, hash chain (SDK: SHA-256 / Server: HMAC-SHA256), PII masking |
| [Transport Security Guide](docs/security/transport-guidelines.md) | TLS/mTLS 必須要件、タイムアウト、再送設計 |
| [Output Sanitization Notice](docs/security/output-sanitization-notice.md) | XSS/injection ペイロードのログ出力注意事項 |
| [Threat Model](docs/design/threat-model.md) | 7 categories, 32 threats (STRIDE + ATT&CK + OWASP) |
| [Security Audit](docs/security-audit/) | Full audit report (SDK 9 files, Server 8 files, cross-cutting 4 files) |
| [Quality Audit](docs/audit/) | テスト品質監査・パッチ設計・実装計画 |
| [Known Limitations](packages/server/docs/design/known-limitations.md) | What's Mock/Interface-only |

### Extending Sentinel

| Document | Description |
|----------|-------------|
| [Extensibility Guide](packages/server/docs/extensibility-guide.md) | Custom rules, adapters, AI providers, storage |
| [Whitelist Management](docs/design/whitelist-management.md) | Modular whitelist, security levels (strict/standard/permissive/off) |
| [Intrusion Detection](docs/design/intrusion-detection.md) | Custom detection rules design |
| [Error Routing](docs/design/error-routing/) | Error classification, routing, and sink design |

### Testing & Quality

| Document | Description |
|----------|-------------|
| [Testing Overview](docs/testing/README.md) | Strategy, classification, design principles |
| [Quality Benchmark](docs/quality-benchmark/checklist-results.md) | 48/48 Google PRR-level checklist |
| [Security Tests](docs/testing/security-tests.md) | 1,464 tests, 20+ CWE attack vectors |

<details>
<summary>All documentation (architecture deep dives, analysis, Go server docs)</summary>

#### Architecture Deep Dives

| Document | Description |
|----------|-------------|
| [Architecture Diagrams](docs/architecture-diagrams.md) | System diagrams, data flow |
| [Config Security Audit](docs/design/config-security-audit/) | YAML/Config security audit (11 findings) |
| [Gap Remediation](docs/design/gap-remediation/) | Design-implementation gap fixes |
| [Runtime Verification](docs/design/runtime-verification/) | deepFreeze, async callback, logicalClock |
| [Final Remediation](docs/design/final-remediation/) | 30 fixes (test integrity, validation, logic bugs) |
| [mTLS & Remaining](docs/design/mtls-and-remaining/) | mTLS support, cert hot-reload, migration guide |

#### Quality Analysis

| Document | Description |
|----------|-------------|
| [Analysis Overview](docs/analysis/README.md) | Analysis log index |
| [Config Reflection](docs/analysis/functional/config-reflection.md) | Config field implementation coverage |
| [Module Integration](docs/analysis/functional/module-integration.md) | Cross-module data flow verification |
| [Feature Completeness](docs/analysis/functional/feature-completeness.md) | Feature status, TODO tracking |
| [Performance](docs/analysis/non-functional/performance.md) | Performance analysis |
| [Resilience](docs/analysis/non-functional/resilience.md) | Fault tolerance |
| [Compatibility](docs/analysis/non-functional/compatibility.md) | ESM/CJS, Node.js compatibility |
| [Dead Code Inventory](docs/analysis/dead-code/inventory.md) | Unused code audit |
| [Improvement Backlog](docs/analysis/roadmap/improvement-backlog.md) | 43 items (41 completed) |

#### Go Server

| Document | Description |
|----------|-------------|
| [Usage Guide (Server)](packages/server/docs/usage-guide.md) | Config, env vars, gRPC API, security levels |
| [Extensibility Guide](packages/server/docs/extensibility-guide.md) | Rules, blocks, notifications, AI, storage |
| [Module Responsibility Map](packages/server/docs/design/module-responsibility-map.md) | Package structure + 10-stage data flow |
| [Threat Response Design](packages/server/docs/design/threat-response-orchestration.md) | Strategy pattern, block, notification design |

</details>

---

## Project Status

| Component | Technology | Status | Tests |
|-----------|-----------|--------|-------|
| Client SDK | TypeScript (zero dependencies) | Implemented | 2,933 tests (Vitest) |
| Backend Server | Go 1.22+ / gRPC | Implemented | 786 tests (`-race` verified, fuzz tested) |
| gRPC Communication | Protocol Buffers v3 | Implemented | E2E verified (22 tests via real gRPC) |

**Total: 3,719 tests (SDK 2,933 + Server 786), 0 FAIL**

---

## Project Structure

> Full file-level documentation: [dir_structure.txt](dir_structure.txt)

```
sentinel/
├── src/                          # TypeScript Client SDK
│   ├── index.ts                  # Public API (Sentinel class)
│   ├── configs/                  # Configuration types, YAML loader
│   ├── core/                     # Ingestion pipeline, detection, task generation
│   ├── security/                 # Hash-chain, PII masking, PII patterns
│   ├── validation/               # Input validator, whitelist registry
│   ├── error-routing/            # Error classification, routing, audit sinks
│   ├── transport/                # RemoteTransport, TaskTransport, HTTP webhook, circuit breaker
│   ├── shared/                   # Error taxonomy, audit utilities
│   └── types/                    # Domain models (Log, Task, Event)
├── tests/                        # 2,933 tests
│   ├── unit/                     # Unit tests (606)
│   ├── config/                   # Config tests (432)
│   ├── security/                 # Security + advanced tests (992)
│   ├── e2e/                      # SDK + Go Server E2E (22)
│   └── integration/              # Pipeline integration (18)
├── packages/server/              # Go Backend Server
│   ├── cmd/server/               # Entry point
│   ├── internal/                 # 10+ packages (engine, detection, security, response, ...)
│   └── proto/                    # Protocol Buffers definition
└── docs/                         # Architecture, security, testing, analysis
```

---

## Configuration (Go Server)

See [Usage Guide](packages/server/docs/usage-guide.md) for full reference.

```yaml
# config/sentinel.yaml
server:
  addr: ":50051"

security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "at-least-32-bytes..."  # or SENTINEL_HMAC_KEY env var

store:
  driver: "sqlite"
  dsn: "file:sentinel.db?_journal=WAL"

ensemble:
  enabled: true
  aggregator: "max"
  threshold: 0.5

response:
  enabled: true
  default_strategy: "NOTIFY_ONLY"
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"
      notify_targets: ["#security"]
```

---

## License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
