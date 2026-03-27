# Sentinel Architecture Diagrams

## 1. System Overview (High Level)

```mermaid
graph TB
    subgraph Clients
        APP1[Application A]
        APP2[Application B]
        APP3[Application C]
    end

    subgraph "TypeScript Client SDK"
        SDK["@sentinel/client<br/>Sentinel.ingest()"]
    end

    subgraph "Go Backend Server"
        GRPC["gRPC Endpoint<br/>:50051"]
        PIPE["Pipeline<br/>(goroutine-safe)"]
    end

    APP1 -->|import| SDK
    APP2 -->|import| SDK
    APP3 -->|import| SDK
    SDK -->|"gRPC / IngestRequest<br/>(Protocol Buffers)"| GRPC
    GRPC --> PIPE

    SDK -. "TS SDKは単体でも<br/>パイプライン実行可能" .-> SDK
```

---

## 2. Pipeline Processing Flow

```mermaid
flowchart TD
    INPUT["Partial&lt;Log&gt;<br/>message, type, level, ..."]

    subgraph "Stage 1: Normalize"
        N1["Validate message<br/>(empty, length, UTF-8, null bytes)"]
        N2["Generate traceId<br/>(UUID v4 if missing)"]
        N3["Apply defaults<br/>(type→SYSTEM, level→3, origin→SYSTEM)"]
        N4["Remove control characters<br/>(keep tab/newline)"]
    end

    subgraph "Stage 2: Mask PII"
        M1["REGEX rules<br/>(custom patterns)"]
        M2["PII_TYPE detection<br/>(EMAIL, CREDIT_CARD,<br/>PHONE, GOVERNMENT_ID)"]
        M3["KEY_MATCH<br/>(sensitive object keys)"]
        M4["Mask fields:<br/>message, actorId,<br/>tags[].category"]
    end

    subgraph "Stage 3: Hash Chain"
        H1["Read previousHash<br/>(mutex-locked)"]
        H2["Deterministic serialize<br/>(keys sorted, hash/sig excluded)"]
        H3["HMAC-SHA256<br/>(server secret key)"]
        H4["Update chain state<br/>(mutex-locked)"]
    end

    subgraph "Stage 4: Detect Events"
        D0{"AI_AGENT origin?<br/>(non-critical)"}
        D1["CriticalRule<br/>isCritical == true"]
        D2["SecurityIntrusionRule<br/>SECURITY && level >= 5"]
        D3["ComplianceViolationRule<br/>COMPLIANCE && 'violation'"]
        D4["SLAViolationRule<br/>SLA && level >= 4"]
    end

    subgraph "Stage 5: Generate Tasks"
        T1["Event name → Rule index lookup"]
        T2["Classify severity<br/>(event + log context)"]
        T3["Filter: actual >= rule threshold"]
        T4["Sort by priority (ascending)"]
        T5["Create GeneratedTask[]"]
    end

    subgraph "Stage 6: Dispatch"
        E1{"requireHumanApproval?"}
        E2{"executionLevel?"}
        E3["Invoke registered handlers"]
        E4["Return TaskResult"]
    end

    OUTPUT["IngestionResult<br/>traceId, hashChainValid,<br/>masked, tasksGenerated[]"]

    INPUT --> N1 --> N2 --> N3 --> N4
    N4 --> M1 --> M2 --> M3 --> M4
    M4 --> H1 --> H2 --> H3 --> H4
    H4 --> D0
    D0 -->|Yes| OUTPUT
    D0 -->|No| D1
    D1 -->|miss| D2
    D2 -->|miss| D3
    D3 -->|miss| D4
    D4 -->|miss| OUTPUT
    D1 -->|hit| T1
    D2 -->|hit| T1
    D3 -->|hit| T1
    D4 -->|hit| T1
    T1 --> T2 --> T3 --> T4 --> T5
    T5 --> E1
    E1 -->|Yes| E4
    E1 -->|No| E2
    E2 -->|AUTO / SEMI_AUTO| E3
    E2 -->|MANUAL| E4
    E2 -->|MONITOR| E4
    E3 --> E4
    E4 --> OUTPUT
```

---

## 3. TypeScript SDK - Module Dependency Graph

```mermaid
graph TD
    INDEX["index.ts<br/><b>Sentinel</b> (public API)"]

    subgraph configs
        SC["sentinel-config.ts<br/>SentinelConfig"]
        MR["masking-rule.ts<br/>MaskingRule"]
    end

    subgraph "core/engine"
        IE["ingestion-engine.ts<br/>IngestionEngine"]
        LN["log-normalizer.ts<br/>LogNormalizer"]
        II["i-interfaces.ts<br/>IIngestionCoordinator<br/>ILogNormalizer"]
        ET["types.ts<br/>IngestionResult"]
    end

    subgraph "core/detection"
        ED["event-detector.ts<br/>EventDetector"]
    end

    subgraph "core/task"
        TG["task-generator.ts<br/>TaskGenerator"]
        SC2["severity-classifier.ts<br/>SeverityClassifier"]
        TE["task-executor.ts<br/>TaskExecutor"]
    end

    subgraph security
        IS["integrity-signer.ts<br/>IntegritySigner"]
        MS["masking-service.ts<br/>MaskingService"]
    end

    subgraph types
        LOG["log.ts<br/>Log, LogType, LogLevel"]
        TASK["task.ts<br/>TaskRule, GeneratedTask, TaskResult"]
        EVENT["event.ts<br/>SystemEventMap, DetectionResult"]
    end

    INDEX --> SC
    INDEX --> IE
    INDEX --> LN
    INDEX --> MS
    INDEX --> IS
    INDEX --> ED
    INDEX --> TG
    INDEX --> TE

    IE --> LN
    IE --> MS
    IE --> IS
    IE --> ED
    IE --> TG
    IE --> TE
    IE --> SC

    LN --> LOG
    LN --> II
    MS --> MR
    ED --> LOG
    ED --> EVENT
    TG --> LOG
    TG --> TASK
    TG --> EVENT
    TG --> SC2
    SC2 --> LOG
    SC2 --> TASK
    SC2 --> EVENT
    TE --> TASK

    IE --> LOG
    IE --> ET
    ET --> TASK
```

---

## 4. Go Server - Package Dependency Graph

```mermaid
graph TD
    MAIN["cmd/server/main.go<br/>(entry point)"]

    subgraph "internal/grpc"
        SRV["server.go<br/>SentinelServer<br/>gRPC handlers"]
        PB["pb/<br/>Generated protobuf"]
    end

    subgraph "internal/engine"
        PIPE["pipeline.go<br/>Pipeline.Process()"]
        NORM["normalizer.go<br/>LogNormalizer"]
    end

    subgraph "internal/detection"
        DET["detector.go<br/>EventDetector<br/>(Rule interface)"]
        RULES["rules.go<br/>CriticalRule<br/>SecurityIntrusionRule<br/>ComplianceViolationRule<br/>SLAViolationRule"]
    end

    subgraph "internal/security"
        SIGN["signer.go<br/>IntegritySigner<br/>(HMAC-SHA256 + Mutex)"]
        MASK["masking.go<br/>MaskingService"]
    end

    subgraph "internal/task"
        GEN["generator.go<br/>TaskGenerator"]
        EXEC["executor.go<br/>TaskExecutor<br/>(RWMutex)"]
    end

    subgraph "internal/domain"
        DLOG["log.go<br/>Log + validations"]
        DTASK["task.go<br/>TaskRule, GeneratedTask"]
        DEVT["event.go<br/>DetectionResult<br/>typed payloads"]
        DRES["result.go<br/>IngestionResult"]
    end

    MAIN --> SRV
    MAIN --> EXEC
    SRV --> PIPE
    SRV --> PB
    PIPE --> NORM
    PIPE --> MASK
    PIPE --> SIGN
    PIPE --> DET
    PIPE --> GEN
    PIPE --> EXEC

    DET --> RULES
    RULES --> DLOG
    RULES --> DEVT
    NORM --> DLOG
    MASK --> DLOG
    SIGN --> DLOG
    GEN --> DTASK
    GEN --> DEVT
    EXEC --> DTASK
    PIPE --> DRES
```

---

## 5. Event Detection Rule Chain (Strategy Pattern)

```mermaid
sequenceDiagram
    participant P as Pipeline
    participant D as EventDetector
    participant R1 as CriticalRule
    participant R2 as SecurityIntrusionRule
    participant R3 as ComplianceViolationRule
    participant R4 as SLAViolationRule

    P->>D: Detect(log)

    Note over D: Check AI_AGENT origin<br/>(skip if non-critical)

    D->>R1: Match(log)
    alt isCritical == true
        R1-->>D: DetectionResult{SYSTEM_CRITICAL_FAILURE}
        D-->>P: result
    else
        R1-->>D: nil
        D->>R2: Match(log)
        alt SECURITY && level >= 5
            R2-->>D: DetectionResult{SECURITY_INTRUSION_DETECTED}
            D-->>P: result
        else
            R2-->>D: nil
            D->>R3: Match(log)
            alt COMPLIANCE && "violation"
                R3-->>D: DetectionResult{COMPLIANCE_VIOLATION}
                D-->>P: result
            else
                R3-->>D: nil
                D->>R4: Match(log)
                alt SLA && level >= 4
                    R4-->>D: DetectionResult{SYSTEM_CRITICAL_FAILURE, MEDIUM}
                    D-->>P: result
                else
                    R4-->>D: nil
                    D-->>P: nil (no event)
                end
            end
        end
    end
```

---

## 6. Task Dispatch Decision Flow

```mermaid
flowchart TD
    TASK["GeneratedTask"]

    CHK1{"guardrails.<br/>requireHumanApproval?"}
    CHK2{"executionLevel?"}
    CHK3{"handlers<br/>registered?"}
    CHK4{"actionType ==<br/>KILL_SWITCH or<br/>AUTOMATED_REMEDIATE?"}

    BLOCKED["blocked_approval"]
    SKIPPED["skipped"]
    DISPATCH["Invoke handler(s)"]
    NOOP["dispatched (noop)"]
    FAIL["failed<br/>(CRITICAL: no handler)"]
    OK["dispatched"]
    ERR["failed<br/>(handler error)"]

    TASK --> CHK1
    CHK1 -->|Yes| BLOCKED
    CHK1 -->|No| CHK2
    CHK2 -->|AUTO| CHK3
    CHK2 -->|SEMI_AUTO| CHK3
    CHK2 -->|MANUAL| BLOCKED
    CHK2 -->|MONITOR| SKIPPED
    CHK3 -->|Yes| DISPATCH
    CHK3 -->|No + defaultHandler| DISPATCH
    CHK3 -->|No handler| CHK4
    CHK4 -->|Yes| FAIL
    CHK4 -->|No| NOOP
    DISPATCH -->|success| OK
    DISPATCH -->|error| ERR
```

---

## 7. gRPC Communication Sequence

```mermaid
sequenceDiagram
    participant C as Client (grpcurl / TS SDK)
    participant S as Go gRPC Server
    participant P as Pipeline
    participant N as LogNormalizer
    participant M as MaskingService
    participant H as IntegritySigner
    participant D as EventDetector
    participant G as TaskGenerator
    participant E as TaskExecutor

    C->>S: IngestRequest (protobuf)

    Note over S: Validate: message non-empty

    S->>P: Process(ctx, log)
    P->>N: Normalize(raw)
    N-->>P: Log (validated)
    P->>M: MaskLog(&log)
    M-->>P: (log.Message, actorId, tags masked)
    P->>H: ApplyHashChain(&log)

    Note over H: mutex.Lock()<br/>read previousHash<br/>compute HMAC-SHA256<br/>update chain<br/>mutex.Unlock()

    H-->>P: (log.Hash set)
    P->>D: Detect(log)

    alt event detected
        D-->>P: DetectionResult
        P->>G: Generate(detection, log)
        G-->>P: []GeneratedTask
        loop each task
            P->>E: Dispatch(task)
            E-->>P: TaskResult
        end
    else no event
        D-->>P: nil
    end

    P-->>S: IngestionResult
    S-->>C: IngestResponse (protobuf)
```

---

## 8. Concurrency Model

```mermaid
graph LR
    subgraph "gRPC Server (goroutine per request)"
        G1["goroutine 1<br/>Ingest()"]
        G2["goroutine 2<br/>Ingest()"]
        G3["goroutine N<br/>Ingest()"]
    end

    subgraph "Pipeline (stateless except signer)"
        NORM["Normalizer<br/>(stateless)"]
        MASK["Masking<br/>(stateless)"]
    end

    subgraph "IntegritySigner (sync.Mutex)"
        SIGN["previousHash<br/>ApplyHashChain()<br/>🔒 Mutex"]
    end

    subgraph "TaskExecutor (sync.RWMutex)"
        EXEC["handlers map<br/>RegisterHandler() 🔒 Write<br/>Dispatch() 🔓 Read"]
    end

    G1 --> NORM
    G2 --> NORM
    G3 --> NORM
    NORM --> MASK
    MASK --> SIGN
    SIGN --> EXEC

    style SIGN fill:#ff9,stroke:#f90
    style EXEC fill:#ff9,stroke:#f90
```
