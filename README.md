# Sentinel

**Intelligent Log-to-Task Automation Platform with Threat Response**

> **Docs**: [使い方](packages/server/docs/usage-guide.md) | [拡張ガイド](packages/server/docs/extensibility-guide.md) | [Docker導入](packages/server/docs/docker-guide.md) | [セキュリティレベル設定](packages/server/docs/usage-guide.md#セキュリティレベル設定) | [設計仕様](packages/server/docs/design/) | [既知の制約](packages/server/docs/design/known-limitations.md)

Sentinel detects events from application logs and automatically generates remediation tasks based on configurable rules. Beyond collection, it provides a pluggable framework for threat analysis (via AI agents), blocking (IP/account, with cloud provider adapter interfaces for AWS/GCP/Azure), and multi-channel notification (Slack/Gmail/Discord/Webhook adapter interfaces).

The system consists of a **TypeScript client SDK** (`@sentinel/client`) and a **Go backend server** communicating over gRPC.

[Architecture](docs/architecture.md) | [Security](docs/security.md) | [Usage Guide](docs/usage-guide.md) | [日本語](readme/ja.md)

---

## Project Status: **v2**

| Component | Technology | Status | Tests |
|-----------|-----------|--------|-------|
| Client SDK | TypeScript (zero dependencies) | Implemented | 184 tests (Vitest) |
| Backend Server | Go 1.22+ / gRPC | Implemented | 614 tests |
| gRPC Communication | Protocol Buffers v3 | Implemented | Server-side E2E verified (SDK→Server gRPC client is user-injected via Transport I/F) |

**Total: 798 tests, 0 FAIL**

---

## What Sentinel Does

```
Application log arrives
    -> [Authorization]  RBAC access control (per-client log type/level restrictions)
    -> [Normalize]      Validate, defaults, sanitize (null bytes, control chars, UTF-8)
    -> [Mask PII]       Context-dependent policy (email, phone, credit card, gov ID)
    -> [Verify]         Post-mask PII residual detection with fallback re-masking
    -> [Hash-chain]     HMAC-SHA256 tamper detection (constant-time comparison)
    -> [Persist]        SQLite with WAL (parameterized queries, SQL injection safe)
    -> [Detect]         Ensemble detection (all rules + dynamic rules + score aggregation)
    -> [Anomaly]        Statistical frequency-based anomaly detection
    -> [Threat Response] Strategy-based: Block IP / Analyze with AI / Notify team
    -> [Generate Task]  Rule-based, severity-filtered, priority-sorted
    -> [Dispatch]       AUTO / SEMI_AUTO / MANUAL / MONITOR + AI agent delegation
```

---

## Architecture

```
┌──────────────────┐                   ┌──────────────────────────────────┐
│  Applications    │     gRPC          │  Go Sentinel Server              │
│                  │  (Transport I/F   │                                  │
│  @sentinel/      │   で接続。利用側  │  Auth → Authz → RateLimit        │
│  client SDK      │   がgRPCクライ   │  Normalize → Mask(Policy)        │
│                  │   アントを注入)   │  Verify → HashChain → Persist    │
│  TypeScript      │  ──────────────>  │  Detect(Ensemble + Anomaly)      │
│  Zero deps       │  <──────────────  │  ThreatResponse(Block/Analyze)   │
│  ESM + CJS       │                   │  TaskGenerate → AgentBridge      │
│                  │                   └──────────────────────────────────┘
│  ローカルでも    │                                  │
│  単独動作可能    │                   ┌──────────────┴──────────────┐
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
※ 通知・AI分析・クラウドブロックは現在Mock/I/F実装。
  実プロバイダ接続は利用側がアダプタを注入する設計。
```

---

## Quick Start

### Go Server

```bash
cd packages/server

# Required: set HMAC key (minimum 32 bytes)
export SENTINEL_HMAC_KEY="your-secret-key-at-least-32-bytes-long"

# Optional: enable enhanced modules via environment variables
export SENTINEL_ENSEMBLE_ENABLED=true
export SENTINEL_ANOMALY_ENABLED=true
export SENTINEL_AGENT_ENABLED=true
export SENTINEL_RESPONSE_ENABLED=true
export SENTINEL_RESPONSE_DEFAULT_STRATEGY=BLOCK_AND_NOTIFY

# Build and run
go build -o sentinel-server ./cmd/server/
./sentinel-server
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
│   ├── index.ts                  # Public API (Sentinel class + SentinelOptions)
│   ├── configs/                  # Configuration types
│   ├── core/
│   │   ├── engine/               # Ingestion pipeline (IngestionEngine)
│   │   ├── detection/            # Event detection rules (EventDetector)
│   │   └── task/                 # Task generation + execution
│   ├── transport/                # RemoteTransport I/F (local/remote/dual)
│   ├── security/                 # Hash-chain, PII masking
│   ├── shared/                   # Error taxonomy, Result monad
│   └── types/                    # Domain models (Log, Task, Event)
├── tests/                        # TS tests (184 cases)
│   ├── unit/                     # Unit tests
│   │   ├── core/                 # Detection, normalizer tests
│   │   ├── security/             # Masking, signer tests
│   │   ├── intelligence/         # Task generator, executor, severity tests
│   │   ├── transport/            # Transport mode tests (local/remote/dual)
│   │   └── shared/               # Result monad tests
│   └── integration/              # Pipeline E2E tests
├── packages/
│   └── server/                   # Go Backend Server
│       ├── cmd/server/           # Entry point (全モジュールワイヤリング)
│       ├── config/               # YAML config + env var overrides + validation
│       ├── internal/
│       │   ├── domain/           # Domain models (Log, Task, Event, Result)
│       │   ├── engine/           # Pipeline(10ステージ) + normalizer + agent bridge
│       │   ├── detection/        # Ensemble + dynamic rules + anomaly + dedup
│       │   ├── security/         # HMAC signer, masking, policy engine, verifier
│       │   ├── response/         # Threat response orchestrator + block agents + cloud adapters
│       │   ├── notify/           # Notification adapters (Slack/Gmail/Discord/Webhook/Log)
│       │   ├── middleware/       # Auth(TokenValidator) + RBAC authorizer + security headers
│       │   ├── task/             # Task generator + executor
│       │   ├── agent/            # AI agent provider(I/F) + executor + mock
│       │   ├── grpc/             # gRPC server + interceptors + pb
│       │   ├── store/            # SQLite persistence (logs/tasks/approvals/threat_responses)
│       │   └── webhook/          # Webhook notifier (approval notifications)
│       ├── proto/                # Protocol Buffers definition (sentinel.proto)
│       ├── docs/design/          # Design documents + work log
│       └── testutil/             # Test fixtures
└── docs/                         # Architecture, security, usage guide
```

---

## Configuration (YAML + Environment Variables)

```yaml
# config/sentinel.yaml
pipeline:
  service_id: "my-service"

security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "at-least-32-bytes..."  # or SENTINEL_HMAC_KEY env var

ensemble:
  enabled: true                     # or SENTINEL_ENSEMBLE_ENABLED=true
  aggregator: "max"                 # max | avg | weighted_sum
  threshold: 0.5
  dedup_window_sec: 10
  dynamic_rules:
    - rule_id: "brute-force"
      event_name: "SECURITY_INTRUSION_DETECTED"
      priority: "HIGH"
      score: 0.95
      conditions:
        log_types: ["SECURITY"]
        min_level: 4
        message_pattern: "(?i)brute\\s*force"

anomaly:
  enabled: true                     # or SENTINEL_ANOMALY_ENABLED=true
  threshold_pct: 300.0

agent:
  enabled: true                     # or SENTINEL_AGENT_ENABLED=true
  provider: "mock"                  # or SENTINEL_AGENT_PROVIDER
  max_loop_depth: 5
  allowed_actions: ["AI_ANALYZE"]
  min_severity: "HIGH"

response:
  enabled: true                     # or SENTINEL_RESPONSE_ENABLED=true
  default_strategy: "NOTIFY_ONLY"   # or SENTINEL_RESPONSE_DEFAULT_STRATEGY
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"
      notify_targets: ["#security"]

authorization:
  enabled: true                     # or SENTINEL_AUTHZ_ENABLED=true
  default_role: "viewer"
  roles:
    admin:
      can_write: true
      can_read: true
      can_approve: true
      can_admin: true
    writer:
      allowed_log_types: ["SYSTEM", "INFRA"]
      max_log_level: 5
      can_write: true
      can_read: true
```

---

## Threat Response Strategies

| Strategy | Behavior |
|---|---|
| `BLOCK_AND_NOTIFY` | Analyze with AI -> Block IP/Account -> Notify with results |
| `ANALYZE_AND_NOTIFY` | Analyze with AI -> Notify with analysis (no block) |
| `NOTIFY_ONLY` | Notify detection result only |
| `BLOCK_ONLY` | Block immediately (silent defense) |
| `MONITOR` | Log only (no action) |

---

## Testing

```bash
# TypeScript SDK (184 tests)
npm test

# Go Server (614 tests)
cd packages/server
go test ./... -race -count=1

# Go Server with verbose output
go test ./... -race -v -count=1
```

---

## Documentation

| Document | Content |
|----------|---------|
| [Server 使い方ガイド](packages/server/docs/usage-guide.md) | 設定詳細、環境変数、gRPC API、セキュリティレベル別推奨設定、SDK連携 |
| [拡張ガイド](packages/server/docs/extensibility-guide.md) | 検知ルール/ブロック手段/通知/AI/ストレージの拡張方法 |
| [Docker導入ガイド](packages/server/docs/docker-guide.md) | Dockerfile、docker-compose、Kubernetes manifest |
| [既知の制約 (N/A)](packages/server/docs/design/known-limitations.md) | 未対応項目・Mock/I/Fのみの機能一覧 |
| [モジュール責務マップ](packages/server/docs/design/module-responsibility-map.md) | パッケージ構成 + 10ステージデータフロー |
| [脅威レスポンス設計](packages/server/docs/design/threat-response-orchestration.md) | 戦略パターン/ブロック/通知の設計仕様 |
| [v2 作業ログ](packages/server/docs/design/work-log-2026-03-27.md) | 全実装フェーズの詳細記録 |
| [docs/architecture.md](docs/architecture.md) | v1 アーキテクチャ |
| [docs/security.md](docs/security.md) | HMAC、PII masking、脅威モデル |

---

## License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
