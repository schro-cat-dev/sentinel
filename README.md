# Sentinel

**AI Agent-based & Deterministic Automation Approach Logging Library for Financial+ Grade By TypeScript**

Sentinel is a TypeScript logging library designed for high-availability financial environments, providing data **durability**, **integrity**, and **privacy** guarantees. One of my private validation projects (exceptionally made public). If you want to read this in JP, please check sentinel/readme/ja.md .

Rather than mere logging, it pursues **Durability**, **Integrity**, and **Privacy** guarantees at physical and mathematical layers. Combines traditional deterministic approaches with AI agents to verify non-deterministic analysis and autonomous response architecture. Serves as a component of personal QA infrastructure projects aiming for automated fault response and business efficiency, with ongoing updates and selective public releases.

Production versioning and npm publication will follow upon achieving sufficient maturity. (edited 2026/1/24)

---

## 🧪 Current Project Status: Alpha (Validation)

> [!WARNING]
> This project is currently in Alpha stage and PoC (Proof of Concept) development phase.
> Some core components use abstractions and mocks.
> Production deployment requires concrete implementations tailored to specific infrastructure requirements.
> Planned for release on npm once quality standards are met and rigorous verification is complete. Currently not at a practical stage for use.

---

## 🦉 Expected Usage

Currently undergoing quality verification and improvement. Please see the intended usage below. Release coming soon.

### 🚀 Quick Start

```typescript
import { Sentinel } from "sentinel";

// Basic initialization
const logger = new Sentinel({
    wal: { enable: true },
    security: { piiMasking: true },
    transport: { cloudwatch: true },
});

// Log output (Auto WAL+Hash-Chaining+PII masking)
logger.info("User login", {
    userId: "123",
    ip: "192.168.1.1",
    ssn: "***-**-1234", // Auto-masked
});

// AI anomaly detection sample
logger.securityAlert("Suspicious activity detected", {
    anomalyScore: 0.92,
    agentAnalysis: "Multiple failed login attempts from new IP",
});
```

---

## 💎 Technical Pillars (Attention⚠️: This lib is in development.)

### 1. Physical Durability (Write-Ahead Logging)

Prevents data loss by persisting to physical disk **before** memory processing.

- **Atomic Writes**: Ingested logs immediately written to WAL (Write-Ahead Log) buffer
- **Fault Recovery**: Recovery sequence on restart minimizes unsent data loss

### 2. Cryptographic Integrity (Hash-Chaining)

Cryptographically links all entries, enabling mathematical verification of temporal data integrity.

$$H_n = \text{SHA256}(L_n \parallel H_{n-1} \parallel \text{Timestamp})$$

Generates tamper-evident audit trail instantly detecting storage tampering (deletion, insertion, modification).

### 3. Scalability & Privacy (WorkerPool & Masking)

Offloads heavy crypto operations from main thread to WorkerPool, preventing main loop blocking while isolating data processing.

- **Parallel Processing**: Signatures and hash operations processed in parallel via WorkerPool
- **PII Masking**: Automatic PII detection and masking at processing pipeline start based on privacy policies

### 4. **AI Agent-based & Deterministic Processing**

Executes autonomous context analysis and decision-making for critical security events via AI agents.

- **Chain of Thought Logging**: Records AI reasoning process within hash-chain for post-hoc auditability
- **Hybrid Orchestration**: Converts non-deterministic LLM analysis into deterministic processing flows ensuring process reliability
- **External System Integration**: API orchestration with external systems enables **autonomous cross-process coordination** based on detected anomalies

---

## 🛠 Architecture

Sentinel separates the entire pipeline from **Ingestion to Transport** into asynchronous tasks, implementing **Backpressure control** to prevent memory overflow and regulate throughput.

1. **Ingestion Engine**: Controls input load and manages WAL writes
2. **Worker Pool**: Isolated thread crypto processing and data transformation
3. **Intelligence Layer**: Anomaly detection and AI task orchestration
4. **Transport Layer**: Secure batch delivery to multiple endpoints

---

## 📂 Project Structure

```text
sentinel/
├── dir_structure.txt
├── docs
│   ├── dir_structure.txt
│   ├── instance-manage.md
│   └── modules-desc.txt
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
│   │   │   └── ingestion-engine.ts
│   │   ├── persistence
│   │   │   ├── i-storage-provider.ts
│   │   │   └── wal-manager.ts
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
│   │   │   ├── i-wal-repository.ts
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
│   ├── proto
│   │   └── wal.proto
│   ├── security
│   │   ├── integrity-signer.ts
│   │   └── masking-service.ts
│   ├── shared
│   │   ├── constants
│   │   │   └── http-status.ts
│   │   ├── errors
│   │   │   ├── app
│   │   │   │   ├── auth-error.ts
│   │   │   │   └── validation-error.ts
│   │   │   ├── app-error.ts
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
│   │   ├── i-log-transport.ts
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

## 🔧 Engineering Specs

| Requirement  | Specification                                   |
| ------------ | ----------------------------------------------- |
| **Runtime**  | Node.js >= 20.0.0                               |
| **Language** | TypeScript 5.x (Strict Mode)                    |
| **Module**   | Pure ESM (Internal) / Dual Build (Distribution) |
| **Testing**  | Vitest (ESM Native)                             |

### Operational Commands

```bash
# Install dependencies
npm install

# Build (generates dist/)
npm run build

# Static analysis (ESLint)
npm run lint

# Unit & integration tests
npm test

```

---

## License

MIT License - Copyright (c) 2026 sy (schro-cat-dev)
