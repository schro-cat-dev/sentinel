# Sentinel

**Intelligent Log-to-Task Automation Platform with Threat Response**

> **Docs**: [使い方](packages/server/docs/usage-guide.md) | [拡張ガイド](packages/server/docs/extensibility-guide.md) | [Docker導入](packages/server/docs/docker-guide.md) | [セキュリティレベル設定](packages/server/docs/usage-guide.md#セキュリティレベル設定) | [設計仕様](packages/server/docs/design/) | [既知の制約](packages/server/docs/design/known-limitations.md)

Sentinel detects events from application logs and automatically generates remediation tasks based on configurable rules. Beyond collection, it provides a pluggable framework for threat analysis (via AI agents), blocking (IP/account, with cloud provider adapter interfaces for AWS/GCP/Azure), and multi-channel notification (Slack/Gmail/Discord/Webhook adapter interfaces).

The system consists of a **TypeScript client SDK** (`@sentinel/client`) and a **Go backend server** communicating over gRPC.

[Architecture](docs/architecture.md) | [Security](docs/security.md) | [Testing](docs/testing/) | [Analysis](docs/analysis/) | [Usage Guide](docs/usage-guide.md) | [日本語](readme/ja.md)

---

## Project Status: **v2**

| Component | Technology | Status | Tests |
|-----------|-----------|--------|-------|
| Client SDK | TypeScript (zero dependencies) | Implemented | 2,159 tests (Vitest) — unit 220 + security 1,227 + config 390 + integration 18 + E2E 22 + detection 22 + whitelist 99 + quality 39 + error-routing 26 + advanced 96 |
| Backend Server | Go 1.22+ / gRPC | Implemented | 689 tests (`-race` verified, fuzz tested) |
| gRPC Communication | Protocol Buffers v3 | Implemented | E2E verified (SDK→Server 15 tests via real gRPC connection) |

**Total: 2,848 tests (SDK 2,159 + Server 689), 0 FAIL**

---

## What Sentinel Does

```
Application log arrives
    -> [Authorization]  RBAC access control (per-client log type/level restrictions)
    -> [Normalize]      Validate, defaults, sanitize (null bytes, control chars, UTF-8)
    -> [Mask PII]       Context-dependent policy (email, phone, credit card, gov ID)
    -> [Verify]         Post-mask PII residual detection with fallback re-masking
    -> [Hash-chain]     HMAC-SHA256 tamper detection (constant-time comparison, async mutex)
    -> [Persist]        SQLite/SQLCipher with WAL (parameterized queries, SQL injection safe)
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

// Register task action handler
sentinel.onTaskAction("SYSTEM_NOTIFICATION", async (task) => {
  console.log(`[${task.severity}] ${task.description}`);
});

// Optional: SEMI_AUTO confirmation handler
sentinel.onTaskConfirm(async (task) => {
  return task.severity === "CRITICAL"; // auto-approve critical only
});

const result = await sentinel.ingest({
  message: "Database connection pool exhausted",
  isCritical: true,
  level: 6,
  boundary: "db-service:pool",
});
// result.tasksGenerated[0].status === "dispatched"
// result.detection?.eventName === "SYSTEM_CRITICAL_FAILURE"

// Graceful shutdown
await sentinel.shutdown();
```

---

## Project Structure

> 全ファイルの責務コメント付き詳細は [dir_structure.txt](dir_structure.txt) を参照。

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
│   ├── validation/               # Runtime input validator (zero-dep)
│   ├── security/                 # Hash-chain, PII masking
│   ├── shared/                   # Error taxonomy, Result monad
│   └── types/                    # Domain models (Log, Task, Event)
├── tests/                        # TS tests (2,102 cases)
│   ├── unit/                     # Unit + validation tests
│   │   ├── core/                 # Engine, detection, normalizer, custom rules tests
│   │   ├── security/             # Masking, signer tests
│   │   ├── intelligence/         # Task generator, executor, severity tests
│   │   ├── validation/           # Whitelist, config validator, lifecycle, metrics tests
│   │   ├── transport/            # Transport mode tests (local/remote/dual)
│   │   ├── validation/           # Input validator tests
│   │   └── shared/               # Result monad tests
│   ├── security/                 # Security tests (94 cases)
│   │   ├── redos.test.ts         # ReDoS resistance (CWE-1333)
│   │   ├── prototype-pollution   # Prototype pollution (CWE-1321)
│   │   ├── input-validation-*    # Validation bypass (CWE-20/626)
│   │   ├── masking-bypass        # PII masking evasion (CWE-200)
│   │   ├── integrity-chain       # Hash chain tamper/replay (CWE-354)
│   │   ├── information-leakage   # Info leak prevention (CWE-209)
│   │   └── new-findings-v2       # Timing, race condition, transport masking
│   ├── e2e/                      # Cross-component E2E (SDK→Go gRPC, 15 cases)
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
│       │   ├── retry/             # Exponential backoff + jitter (shared module)
│       │   ├── store/            # SQLite/SQLCipher persistence (logs/tasks/approvals/threat_responses)
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
server:
  addr: ":50051"
  # tls_cert_file: "/path/to/cert.pem"  # TLS有効化
  # tls_key_file: "/path/to/key.pem"

pipeline:
  service_id: "my-service"

security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "at-least-32-bytes..."  # or SENTINEL_HMAC_KEY env var
  hmac_key_version: 1               # キーローテーション用

store:
  driver: "sqlite"                   # sqlite / sqlite_encrypted
  dsn: "file:sentinel.db?_journal=WAL"
  # encryption_key: via SENTINEL_STORE_ENCRYPTION_KEY env var

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
  block_mode: "IMMEDIATE"           # IMMEDIATE / REQUIRE_APPROVAL
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"
      notify_targets: ["#security"]

auth:
  enabled: false                    # or SENTINEL_API_KEYS で有効化
  rate_limit_rps: 10                # default: 10 (security hardened)
  rate_limit_burst: 50

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

# masking_policies: []              # ログ種別ごとのマスクルール
# routing_rules: []                 # 承認チェーンルーティング
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
# TypeScript SDK (2,159 tests)
npm test

# Go Server (689 tests)
cd packages/server
go test ./... -race -count=1
```

**Total: 2,848 tests (SDK 2,159 + Server 689), 0 FAIL**

| カテゴリ | テスト数 | 詳細ドキュメント |
|---------|---------|----------------|
| Unit | 220 | [docs/testing/unit-tests.md](docs/testing/unit-tests.md) |
| Security | 94 | [docs/testing/security-tests.md](docs/testing/security-tests.md) |
| Advanced Security | 1,203 | Fuzzing, encoding bypass, injection, DoS, state manipulation |
| Config Matrix | 390 | [docs/testing/config-tests.md](docs/testing/config-tests.md) |
| Detection Rules | 22 | Custom detection rules (正常/異常/エッジ/ペネトレーション) |
| Whitelist Validation | 99 | Registry, config validator, routing E2E, security levels |
| Quality / Lifecycle | 39 | Instance lifecycle, pollution guard, metrics, audit fixes |
| Integration | 18 | [docs/testing/integration-e2e-tests.md](docs/testing/integration-e2e-tests.md) |
| E2E (SDK→Go) | 15 | [docs/testing/integration-e2e-tests.md](docs/testing/integration-e2e-tests.md) |
| Go Server | 689 | `go test ./... -race` |
| **品質ベンチマーク** | 48/48 | [docs/quality-benchmark/checklist-results.md](docs/quality-benchmark/checklist-results.md) |

---

## Documentation

### アーキテクチャ・設計

| Document | Content |
|----------|---------|
| [Architecture](docs/architecture.md) | SDK + Server パイプラインフロー、モジュール責務マップ |
| [Security](docs/security.md) | 脅威モデル、HMAC hash chain、PII masking、バリデーション境界 |
| [Architecture Diagrams](docs/architecture-diagrams.md) | システム構成図、データフロー図 |
| [Whitelist Management](docs/design/whitelist-management.md) | モジュラーホワイトリスト管理・2階層構造・セキュリティレベル制御 |
| [Intrusion Detection](docs/design/intrusion-detection.md) | 不正アクセス検知設計・カスタムルール・責務分担 |
| [Error Routing](docs/design/error-routing/) | エラールーティング層設計（分類→ルーティング→実行、外部サービス連携） |
| [Threat Model](docs/design/threat-model.md) | 脅威モデル概要（7カテゴリ32脅威、STRIDE+ATT&CK+OWASP） |
| [Security Levels](docs/design/whitelist-security-levels.md) | ホワイトリストセキュリティレベル（strict/standard/permissive/off）運用ガイド |

### テスト

| Document | Content |
|----------|---------|
| [Testing Overview](docs/testing/README.md) | テスト戦略・分類・設計原則 |
| [Unit Tests](docs/testing/unit-tests.md) | 220テストの一覧・各テストの設計根拠 |
| [Security Tests](docs/testing/security-tests.md) | 94テスト・17攻撃ベクトルのカバレッジ |
| [Config Tests](docs/testing/config-tests.md) | 322テスト・全設定パターンの正常/異常/エッジケース |
| [Integration & E2E](docs/testing/integration-e2e-tests.md) | 33テスト・SDK→Go gRPC通信テスト |
| [Quality Checklist](docs/testing/quality-checklist.md) | 50+項目の定性的チェックリスト |

### 内部品質解析

| Document | Content |
|----------|---------|
| [Analysis Overview](docs/analysis/README.md) | 解析ログの索引・タイムスタンプ規約 |
| [Config Reflection](docs/analysis/functional/config-reflection.md) | 設定フィールドの実装反映状況 |
| [Module Integration](docs/analysis/functional/module-integration.md) | モジュール間連携の完全性・データフロー検証 |
| [Feature Completeness](docs/analysis/functional/feature-completeness.md) | 機能実装状況・TODO追跡 |
| [Performance](docs/analysis/non-functional/performance.md) | パフォーマンス解析 |
| [Resilience](docs/analysis/non-functional/resilience.md) | 耐障害性・フォールトトレランス |
| [Observability](docs/analysis/non-functional/observability.md) | 可観測性・ログ・メトリクス |
| [Compatibility](docs/analysis/non-functional/compatibility.md) | ESM/CJS・Node.js互換性 |
| [Dead Code Inventory](docs/analysis/dead-code/inventory.md) | 未使用コードの棚卸し |

### 品質ベンチマーク

| Document | Content |
|----------|---------|
| [Quality Standards](docs/quality-benchmark/standards.md) | Google PRR水準の10カテゴリ49項目ベンチマーク基準 |
| [Checklist Results](docs/quality-benchmark/checklist-results.md) | 全項目のPASS/FAIL結果・修正記録 |
| [Instance Management Audit](docs/quality-benchmark/instance-management-audit.md) | インスタンスライフサイクル・可変状態・並行性の詳細監査 |
| [Improvement Backlog](docs/analysis/roadmap/improvement-backlog.md) | 37件の優先度付き改善バックログ（35完了） |

### Go Server

| Document | Content |
|----------|---------|
| [使い方ガイド](packages/server/docs/usage-guide.md) | 設定詳細、環境変数、gRPC API、セキュリティレベル別推奨設定 |
| [拡張ガイド](packages/server/docs/extensibility-guide.md) | 検知ルール/ブロック手段/通知/AI/ストレージの拡張方法 |
| [Docker導入ガイド](packages/server/docs/docker-guide.md) | Dockerfile、docker-compose、Kubernetes manifest |
| [既知の制約](packages/server/docs/design/known-limitations.md) | 未対応項目・Mock/I/Fのみの機能一覧 |
| [モジュール責務マップ](packages/server/docs/design/module-responsibility-map.md) | パッケージ構成 + 10ステージデータフロー |
| [脅威レスポンス設計](packages/server/docs/design/threat-response-orchestration.md) | 戦略パターン/ブロック/通知の設計仕様 |
| [v2 作業ログ](packages/server/docs/design/work-log-2026-03-27.md) | 全実装フェーズの詳細記録 |

---

## License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
