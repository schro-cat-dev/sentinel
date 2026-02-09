# Sentinel (Note: This is a draft document.)

**AI Agent-Driven Task Automation Middleware Server with Deterministic Guarantees for Mission-Critical Systems**

Sentinel is a **TypeScript logging library** and **Go-based middleware server** designed to integrate with SIEM/XDR tools, trigger AI agent-based automatic patching and task execution, and serve as a lightweight logging client for production environments.

This project **will explore** experimental task generation from historical log data while **planning** financial-grade durability, integrity, and privacy guarantees through advanced cryptographic measures including hash-chaining and precise metadata management.

The main server **will operate** as a middleware server with nginx-like proxy capabilities,
handling authentication (mTLS/JWT), rate limiting, and full task orchestration lifecycle management.
**Currently in design phase** with planned npm publication as `@sentinel/client`. [日本語README](sentinel/readme/ja.md)

---

## 🧪 Current Project Status: **Design Phase**

> [!WARNING]
> **Not functional - Design/Development phase**
>
> ⚠️ **Architecture design in progress** (hash-chaining/WAL evaluation)
> ⚠️ **Go middleware server design started**
> ⚠️ **No executable code yet**
> 🎯 **Design complete → MVP → npm publication (Q2-Q3 2026 target)**

---

## 🎯 Planned Core Objectives

1. **SIEM/XDR Integration** - Seamless API connectivity with Splunk, Elastic, Microsoft Sentinel, CrowdStrike, and other security monitoring platforms
2. **AI Agent-Driven Automation** - Automatic patch generation and task execution triggered by log analysis using external AI services (OpenAI, Anthropic, etc.)
3. **Historical Log-Based Task Generation** - Experimental pattern recognition from accumulated logs for proactive task creation (acknowledged limited precision, research purposes)
4. **Go-Based Main Server** - **Middleware server** with nginx-like proxy capabilities, handling authentication, rate limiting, **and full task orchestration lifecycle**
5. **Lightweight npm Logging Library** - `@sentinel/client` for developer-friendly integration
6. **Sentry/Datadog Ecosystem Integration** - Server-side webhook receivers for metrics, traces, and alerts from monitoring platforms
7. **Authentication & Authorization** - Comprehensive mTLS and JWT-based service authentication with service-specific rate limiting

---

## 🔒 Planned Architectural Guarantees **(Design Phase)**

### **Data Integrity & Tamper Resistance** _(Under Design)_

- **Hash-Chaining**: Sequential cryptographic linking of log entries using
  \(H*n = \text{SHA256}(L_n \parallel H*{n-1} \parallel \text{timestamp} \parallel \text{serviceId})\)
- **Metadata Precision**: Atomic recording of service context, temporal relationships, and processing lineage
- **Tamper Detection**: Mathematical verification prevents insertion, deletion, or modification attacks

### **Durability & Consistency** _(Under Design)_

- Exploring multiple persistence strategies including WAL patterns, distributed storage, and atomic batching
- Planned evaluation of integrity-completeness tradeoffs for production deployment

---

## 🏗 Planned System Architecture

```

┌─────────────────┐ gRPC/mTLS ┌──────────────────┐ ┌──────────────┐
│ Applications │ ──────────▶ │ Go Sentinel API │▶ │ DynamoDB │
│ (@sentinel/ │ │ (middleware) │ │ (Task Recipes │
│ client) │ │ Auth/Rate-limit │ │ + Metadata) │
└─────────────────┘ └──────────────────┘ └──────────────┘
▲ │ Redis Streams
┌────┼──────┐ ┌─────────▼──────────┐
│Sentry│ │ │ Lambda Workers │
│Datadog│ │ │ - AI Agents │
│SIEM │ │ │ - Patch Generator │
└─────┴──────┘ │ - SIEM Integration│
└────────────────────┘

```

**Design Philosophy**: Cost-optimized architecture through precise component selection minimizing operational overhead while maximizing automation effectiveness.

---

## 📋 Planned Component Specifications

| Component        | Technology     | Role                                                           | Status       |
| ---------------- | -------------- | -------------------------------------------------------------- | ------------ |
| **Client SDK**   | TypeScript/ESM | Developer logging interface                                    | Design phase |
| **Main Server**  | Go             | **Middleware server**: auth, rate limiting, task orchestration | Design phase |
| **Task Storage** | DynamoDB       | Recipe lookup, metadata preservation                           | Design phase |
| **Task Queue**   | Redis Streams  | Asynchronous AI/SIEM execution                                 | Design phase |
| **Automation**   | AWS Lambda     | AI agent execution, external integrations                      | Design phase |

---

## 🔐 Planned Authentication & Authorization **(Design Phase)**

**Phase 1**: JWT Service Tokens + API Key rotation _(planned)_
**Phase 2**: mTLS mutual authentication with service-specific certificate management _(under design)_
**Phase 3**: Service mesh integration (Linkerd/Istio) for zero-trust environments _(evaluation)_

```

ServiceA → mTLS → Sentinel API → DynamoDB → Lambda AI Agent → SIEM
↖ ServiceB certificates auto-rotated every 90 days

```

---

## 🤝 Planned Integration Ecosystem

```

**Input Sources**: Monitoring tools, SIEM/XDR platforms via Webhook/API
**Output Actions**: AI services, Git automation, Infrastructure APIs

```

---

## 📂 Project Structure

### Planned Structure

```

sentinel/
├── packages/
│ ├── client/ # @sentinel/client npm package
│ ├── api/ # Go main server (middleware)
│ └── workers/ # Lambda AI/SIEM automation
├── deploy/ # Infrastructure as Code
├── docs/ # Architecture + Integration guides
└── examples/ # Integration patterns

```

### Current Structure (Early Development)

```

sentinel/
├── dir_structure.txt
├── docs
│   ├── coop-siem-like-tools-agent.md
│   ├── dir_structure.txt
│   ├── instance-manage.md
│   ├── modules-desc.txt
│   └── task-gen.md
├── eslint.config.js
├── package-lock.json
├── package.json
├── readme
│   ├── en(default).md
│   └── ja.md
├── README.md
├── rollup.config.js
├── samples
│   ├── basic_usage.ts
│   └── security_anomaly_ai.ts
├── src
│   ├── bootstrap
│   │   ├── di-container.ts
│   │   └── worker-pool.ts
│   ├── configs
│   │   ├── detailed-config.ts
│   │   └── global-config.ts
│   ├── core
│   │   ├── engine
│   │   │   ├── i-interfaces.ts
│   │   │   ├── index.ts
│   │   │   ├── ingestion-engine.ts
│   │   │   ├── log-normalizer.ts
│   │   │   ├── persistence-layer.ts
│   │   │   ├── queue-adapter.ts
│   │   │   ├── recovery-service.ts
│   │   │   └── types.ts
│   │   └── system
│   │       └── i-env-provider.ts
│   ├── generated
│   │   └── src
│   │       └── proto
│   │           └── wal.ts
│   ├── index.ts
│   ├── infra
│   │   └── wal
│   │       ├── atomic-file.ts
│   │       ├── file-lock.ts
│   │       └── wal-mapper.ts
│   ├── infrastructure
│   │   ├── persistence
│   │   │   ├── i-storage-provider.ts
│   │   │   ├── i-wal-repository.ts
│   │   │   ├── wal-manager.ts
│   │   │   └── wal-repository.ts
│   │   ├── security
│   │   └── system
│   │       └── environment-metadata.ts
│   ├── intelligence
│   │   ├── ai
│   │   │   ├── i-agent-provider.ts
│   │   │   └── openai-agent-provider.ts
│   │   ├── detector
│   │   │   └── event-detector.ts
│   │   └── task
│   │       ├── i-task-repository.ts
│   │       ├── sql-task-repository.ts
│   │       └── task-manager.ts
│   ├── lib
│   │   ├── crypto
│   │   │   ├── aesGcmEncryptionStrategy.ts
│   │   │   ├── cryptoFactory.ts
│   │   │   ├── cryptoTypes.ts
│   │   │   ├── index.ts
│   │   │   └── keyDerivation.ts
│   │   ├── env
│   │   │   ├── di.ts
│   │   │   ├── factory.ts
│   │   │   ├── index.ts
│   │   │   ├── types.ts
│   │   │   └── validator.ts
│   │   └── time
│   │       └── date-time-provider.ts
│   ├── proto
│   │   └── wal.proto
│   ├── security
│   │   ├── integrity-signer.ts
│   │   └── masking-service.ts
│   ├── shared
│   │   ├── constants
│   │   │   ├── error-layer.ts
│   │   │   ├── error-protocol-kind.ts
│   │   │   ├── http-status.ts
│   │   │   ├── index.ts
│   │   │   ├── infra
│   │   │   │   ├── cache
│   │   │   │   ├── datastore
│   │   │   │   ├── db
│   │   │   │   │   └── db-error-kind.ts
│   │   │   │   └── storage
│   │   │   └── kinds
│   │   │       ├── application
│   │   │       │   ├── access.ts
│   │   │       │   ├── auth.ts
│   │   │       │   ├── index.ts
│   │   │       │   ├── limit-over.ts
│   │   │       │   ├── permission.ts
│   │   │       │   ├── security.ts
│   │   │       │   └── validation.ts
│   │   │       ├── index.ts
│   │   │       └── persistence
│   │   │           ├── cache-error-kind.ts
│   │   │           ├── datastore-error-kind.ts
│   │   │           ├── db-error-kind.ts
│   │   │           ├── index.ts
│   │   │           └── storage-error-kind.ts
│   │   ├── errors
│   │   │   ├── app
│   │   │   │   ├── auth-error.ts
│   │   │   │   └── validation-error.ts
│   │   │   ├── error-payload-protocol.ts
│   │   │   ├── index.ts
│   │   │   └── infra
│   │   │       ├── db-error.ts
│   │   │       └── wal-error.ts
│   │   ├── functional
│   │   │   └── result.ts
│   │   └── utils
│   │       ├── error-utils.ts
│   │       ├── guard-wal-entry-raw.ts
│   │       └── seed-to-union-types.ts
│   ├── transport
│   │   ├── batch-transport.ts
│   │   ├── cloudwatch-transport.ts
│   │   ├── datadog-transport.ts
│   │   ├── http-transport.ts
│   │   ├── i-log-transport.ts
│   │   ├── index.ts
│   │   └── transport-manager.ts
│   ├── types
│   │   ├── agent.ts
│   │   ├── event.ts
│   │   ├── log.ts
│   │   └── task.ts
│   └── workers
│       └── log.worker.ts
├── tests
├── tsconfig.json
├── types
│   └── global.d.ts
└── util-commands.md

```

---

## 🎛 Planned Operational Commands

```bash
# Client development
cd packages/client
npm install && npm run build

# API development
cd packages/api
go build -ldflags="-s -w" -o sentinel-api

# Infrastructure provisioning
cd deploy
terraform apply
```

---

## 🔮 Current Design Focus Areas **(All Under Design)**

- **Data integrity mechanisms DESIGN** (hash-chaining, WAL patterns, distributed consensus)
- **Completeness guarantees DESIGN** for task execution lineage and metadata preservation
- **Cost-performance optimization** through precise infrastructure right-sizing evaluation
- **Authentication evolution DESIGN** from JWT to production-grade mTLS service mesh

---

## 📄 License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
