# Sentinel Usage Guide

## Table of Contents

1. [TypeScript Client SDK](#typescript-client-sdk)
   - [Install](#install) / [Initialize](#initialize) / [Ingest Logs](#ingest-logs)
   - [Register Task Handlers](#register-task-handlers) / [SEMI_AUTO Confirmation](#semi_auto-confirmation-handler)
   - [Error Handling](#error-handling) / [Size Limits](#size-limits-validationlimits)
   - [Shutdown](#shutdown) / [Reset](#reset-testing)
2. [Go Backend Server](#go-backend-server)
3. [Configuration Reference](#configuration-reference)
4. [Task Rules Reference](#task-rules-reference)
5. [Event Detection Reference](#event-detection-reference)

---

## TypeScript Client SDK

### Install

本パッケージは npm registry には未公開です。リポジトリを clone してローカル参照で利用してください。

```bash
# リポジトリを clone
git clone https://github.com/schro-cat-dev/sentinel.git

# ビルド
cd sentinel && npm install && npm run build

# 別プロジェクトからローカルパスで参照
npm install ../path/to/sentinel
```

> **Note:** 将来的に npm registry に公開された場合は `npm install @schro-cat-dev/sentinel` で利用可能になります。

Requirements: Node.js >= 20.0.0

Dependencies: **none** (zero npm dependencies, uses only `node:crypto`)

### Initialize

```typescript
import { Sentinel, createDefaultConfig } from "@schro-cat-dev/sentinel";

const sentinel = Sentinel.initialize(createDefaultConfig({
  projectName: "my-app",
  serviceId: "payment-service-01",
  environment: "production",
  masking: {
    enabled: true,
    rules: [
      { type: "PII_TYPE", category: "EMAIL" },
      { type: "PII_TYPE", category: "CREDIT_CARD" },
      { type: "PII_TYPE", category: "PHONE" },
      { type: "KEY_MATCH", sensitiveKeys: ["password", "ssn", "secret"] },
    ],
    preserveFields: ["traceId", "spanId"],
  },
  security: { enableHashChain: true },
  taskRules: [ /* see Task Rules Reference */ ],
}));
```

`Sentinel.initialize()` はシングルトン。2回目以降は同じインスタンスを返す。

### Ingest Logs

```typescript
const result = await sentinel.ingest({
  message: "User login successful",          // required
  type: "SECURITY",                          // optional (default: "SYSTEM")
  level: 3,                                  // optional (default: 3)
  boundary: "AuthService:login",             // optional (default: "unknown")
  isCritical: false,                         // optional (default: false)
  origin: "SYSTEM",                          // optional (default: "SYSTEM")
  actorId: "user-123",                       // optional
  traceId: "custom-trace-id",                // optional (auto-generated UUID if omitted)
  tags: [{ key: "ip", category: "10.0.0.1" }], // optional
  resourceIds: ["account-456"],              // optional
});

// result:
// {
//   traceId: "custom-trace-id",
//   hashChainValid: true,
//   masked: true,
//   tasksGenerated: [],
//   detection: null          // イベント検知時: { eventName: "...", priority: "HIGH" }
// }
```

### Register Task Handlers

```typescript
sentinel.onTaskAction("SYSTEM_NOTIFICATION", async (task) => {
  await fetch("https://hooks.slack.com/services/xxx", {
    method: "POST",
    body: JSON.stringify({
      text: `[${task.severity}] ${task.description}\nSource: ${task.sourceLog.boundary}`,
    }),
  });
});

sentinel.onTaskAction("AI_ANALYZE", async (task) => {
  // Forward to Go server or AI service
  console.log(`Analysis requested: ${task.sourceLog.message}`);
});

sentinel.onTaskAction("ESCALATE", async (task) => {
  // Create ticket in issue tracker
  console.log(`Escalation: ${task.description} (${task.sourceLog.traceId})`);
});
```

### Task Transport Adapters

外部システム（Slack, Jira, SIEM等）へのタスク配信は `TaskTransport` アダプタで拡張可能。
既存の `onTaskAction` コールバック方式と **共存** する。

```typescript
import type { TaskTransport } from "@schro-cat-dev/sentinel";

// 利用者がアダプタを実装
const slackTransport: TaskTransport = {
    name: "slack-webhook",
    async dispatch(task) {
        const res = await fetch("https://hooks.slack.com/services/xxx", {
            method: "POST",
            body: JSON.stringify({
                text: `[${task.severity}] ${task.description}\nTrace: ${task.sourceLog.traceId}`,
            }),
        });
        return {
            transportName: "slack-webhook",
            success: res.ok,
            externalId: res.ok ? await res.text() : undefined,
            error: res.ok ? undefined : `HTTP ${res.status}`,
        };
    },
    async close() {
        // 必要に応じて接続クリーンアップ
    },
};

// 初期化時に注入
const sentinel = Sentinel.initialize(config, {
    taskTransports: [slackTransport],
});
```

**コールバック vs トランスポートの使い分け:**

| 方式 | 用途 | 特徴 |
|------|------|------|
| `onTaskAction` (コールバック) | インプロセスの処理、軽量な通知 | actionType単位で登録、maxRetries適用 |
| `taskTransports` (アダプタ) | 外部システム連携、構造化された結果返却 | 全タスクを受取、`TaskTransportResult` で成否を返す |

両方を同時に使用可能。ハンドラ→トランスポートの順に実行され、片方の失敗がもう片方をブロックしない。

### SEMI_AUTO Confirmation Handler

```typescript
// SEMI_AUTO タスクの自動承認/拒否を制御
sentinel.onTaskConfirm(async (task) => {
  // CRITICAL のみ自動承認、それ以外はブロック
  return task.severity === "CRITICAL";
});
```

確認ハンドラ未登録の場合、SEMI_AUTO は AUTO と同じ動作（後方互換）。

### Error Handling

```typescript
const sentinel = Sentinel.initialize(createDefaultConfig({
  projectName: "my-app",
  serviceId: "svc",
  // パイプライン内部のswallowされるエラーを受け取る
  onError: (error, context) => {
    console.error(`[Sentinel] ${context}: ${error.message}`);
    // context: "callback", "transport.dual" 等
  },
  // SDK内部のログ出力先を制御（省略時はconsole出力なし）
  logger: {
    warn: (msg) => myLogger.warn(`[Sentinel] ${msg}`),
    error: (msg) => myLogger.error(`[Sentinel] ${msg}`),
  },
}));
```

### Size Limits (ValidationLimits)

```typescript
// デフォルト制限値を確認
import { DEFAULT_VALIDATION_LIMITS } from "@schro-cat-dev/sentinel";
// {
//   maxMessageLength: 65536,      maxDetailsLength: 65536,
//   maxStringFieldLength: 512,    maxInputSize: 1_048_576 (1MB),
//   maxTotalLogSize: 2_097_152 (2MB), ...
// }

// 大きなペイロードを扱う場合はオーバーライド
const sentinel = Sentinel.initialize(createDefaultConfig({
  projectName: "my-app",
  serviceId: "svc",
  validationLimits: {
    maxInputSize: 5_000_000,      // input フィールドを5MBまで許容
    maxTotalLogSize: 10_000_000,  // ログ全体を10MBまで許容
    maxStringFieldLength: 2048,   // actorId等の文字列フィールドを2KBまで
  },
}));
```

### Shutdown

```typescript
// グレースフルシャットダウン: Transport接続を閉じ、TaskTransport.close()を呼び、ハンドラをクリア
await sentinel.shutdown();

// shutdown後は再initializeが必要
const newSentinel = Sentinel.initialize(newConfig);
```

### Reset (Testing)

```typescript
Sentinel.reset(); // Clears singleton, allows re-initialization
```

### Build

```bash
npm run build      # TypeScript compile + Rollup bundle
npm run typecheck   # Type check only
npm run test        # Run 1,899 tests (Vitest)
npm run lint        # ESLint
```

Output: `dist/index.cjs` (CommonJS) + `dist/index.mjs` (ESM) + `dist/index.d.ts` (types)

---

## Go Backend Server

### Prerequisites

- Go 1.22+
- protoc (Protocol Buffers compiler)
- protoc-gen-go, protoc-gen-go-grpc

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### Build

```bash
cd packages/server
go build -o sentinel-server ./cmd/server/
```

### Run

```bash
# Required: HMAC key (minimum 32 bytes)
export SENTINEL_HMAC_KEY="$(openssl rand -base64 32)"

# Optional: listen address (default :50051)
export SENTINEL_ADDR=":50051"

./sentinel-server
# {"level":"INFO","msg":"server listening","addr":":50051"}
```

The server refuses to start if `SENTINEL_HMAC_KEY` is not set or is shorter than 32 bytes.

### Environment Variables

| Variable | Required | Default | Description |
|----------|---------|---------|-------------|
| `SENTINEL_HMAC_KEY` | Yes | (none) | HMAC-SHA256 key for hash chain integrity. Minimum 32 bytes. |
| `SENTINEL_ADDR` | No | `:50051` | gRPC listen address |
| `SENTINEL_API_KEYS` | No | (none) | API keys for authentication (comma-separated) |
| `SENTINEL_ENSEMBLE_ENABLED` | No | `false` | Enable ensemble detection |
| `SENTINEL_ANOMALY_ENABLED` | No | `false` | Enable anomaly detection |
| `SENTINEL_AGENT_ENABLED` | No | `false` | Enable AI agent |
| `SENTINEL_AGENT_PROVIDER` | No | `mock` | AI provider name |
| `SENTINEL_AUTHZ_ENABLED` | No | `false` | Enable RBAC authorization |
| `SENTINEL_RESPONSE_ENABLED` | No | `false` | Enable threat response |
| `SENTINEL_RESPONSE_DEFAULT_STRATEGY` | No | `NOTIFY_ONLY` | Default response strategy |
| `SENTINEL_STORE_ENCRYPTION_KEY` | No | (none) | SQLCipher encryption key (auto-enables sqlite_encrypted driver) |
| `SENTINEL_SLACK_WEBHOOK_URL` | No | (none) | Slack notification webhook |
| `SENTINEL_DISCORD_WEBHOOK_URL` | No | (none) | Discord notification webhook |
| `SENTINEL_GMAIL_FROM` | No | (none) | Gmail sender address |
| `SENTINEL_GMAIL_PASSWORD` | No | (none) | Gmail app password |

### gRPC API

#### IngestRequest

```protobuf
message IngestRequest {
  string trace_id = 1;        // Optional. Auto-generated UUID if empty.
  string type = 2;             // SYSTEM, SECURITY, COMPLIANCE, INFRA, SLA, DEBUG, BUSINESS-AUDIT
  int32 level = 3;             // 1-6 (1=trace, 6=critical)
  string boundary = 4;         // Source module (e.g. "AuthService:login")
  string service_id = 5;       // Overridden by server config
  bool is_critical = 6;        // Triggers SYSTEM_CRITICAL_FAILURE detection
  string message = 7;          // Required. Max 65536 chars. Must be valid UTF-8.
  string origin = 8;           // SYSTEM or AI_AGENT
  repeated LogTag tags = 9;    // Key-value metadata
  string actor_id = 10;        // User/service ID (subject to PII masking)
  string span_id = 11;         // Distributed tracing span
  string parent_span_id = 12;  // Parent span
  repeated string resource_ids = 13; // Affected resource IDs
}
```

#### IngestResponse

```protobuf
message IngestResponse {
  string trace_id = 1;
  bool hash_chain_valid = 2;
  bool masked = 3;
  repeated TaskResult tasks_generated = 4;
}

message TaskResult {
  string task_id = 1;
  string rule_id = 2;
  string status = 3;           // dispatched, blocked_approval, skipped, failed
  string dispatched_at = 4;
  string error = 5;
}
```

#### HealthCheck

```protobuf
rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
// Returns: { status: "SERVING", version: "0.3.0" }
```

### Test with grpcurl

```bash
# Health check
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  localhost:50051 sentinel.v1.SentinelService/HealthCheck

# Normal log
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  -d '{"message":"User login","type":"SYSTEM","level":3}' \
  localhost:50051 sentinel.v1.SentinelService/Ingest

# Critical log (triggers task)
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  -d '{"message":"DB pool exhausted","level":6,"is_critical":true,"boundary":"db-service"}' \
  localhost:50051 sentinel.v1.SentinelService/Ingest

# Security intrusion (triggers task)
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  -d '{"message":"Brute force","type":"SECURITY","level":5,"tags":[{"key":"ip","category":"10.0.0.1"}]}' \
  localhost:50051 sentinel.v1.SentinelService/Ingest

# AI_AGENT log (no re-detection)
grpcurl -plaintext -import-path proto -proto sentinel.proto \
  -d '{"message":"Agent report","type":"SECURITY","level":5,"origin":"AI_AGENT"}' \
  localhost:50051 sentinel.v1.SentinelService/Ingest
```

### Run Tests

```bash
cd packages/server

# All tests with race detector
go test ./... -race -count=1

# Verbose
go test ./... -race -v -count=1

# Specific package
go test ./internal/security/ -race -v -count=1
```

---

## Configuration Reference

### SentinelConfig (TypeScript SDK)

| Field | Type | Required | Default | Description |
|-------|------|---------|---------|-------------|
| `projectName` | string | Yes | - | Project identifier |
| `serviceId` | string | Yes | - | Service identifier for distributed tracing |
| `environment` | string | No | `"development"` | `production`, `staging`, `development`, `local`, `test` |
| `masking.enabled` | boolean | No | `false` | Enable PII masking |
| `masking.rules` | MaskingRule[] | No | `[]` | Masking rule definitions |
| `masking.preserveFields` | string[] | No | `["traceId","spanId"]` | Fields exempt from masking |
| `security.enableHashChain` | boolean | No | `true` | Enable HMAC-SHA256 hash chain |
| `taskRules` | TaskRule[] | No | `[]` | Task auto-generation rules |
| `taskTransportConfigs` | TaskTransportConfig[] | No | `undefined` | YAML由来のトランスポート設定メタデータ |
| `onLogProcessed` | function | No | - | Callback: fired after each log is processed |
| `onTaskGenerated` | function | No | - | Callback: fired when a task is generated |
| `onTaskDispatched` | function | No | - | Callback: fired when a task is dispatched |

### PipelineConfig (Go Server)

| Field | Type | Required | Default | Description |
|-------|------|---------|---------|-------------|
| `ServiceID` | string | Yes | - | Server service identifier |
| `EnableHashChain` | bool | No | `false` | Enable HMAC-SHA256 hash chain |
| `EnableMasking` | bool | No | `false` | Enable PII masking |
| `MaskingRules` | []MaskingRule | No | `nil` | Masking rule definitions |
| `PreserveFields` | []string | No | `nil` | Fields exempt from masking |
| `TaskRules` | []TaskRule | No | `nil` | Task generation rules |
| `HMACKey` | []byte | Conditional | - | Required when `EnableHashChain` is `true`. Minimum 32 bytes. |

### MaskingRule

| Type | Fields | Example |
|------|--------|---------|
| `REGEX` | `pattern` (RegExp), `replacement` (string), `description` (string) | `{ type: "REGEX", pattern: /secret-\d+/, replacement: "[REDACTED]", description: "mask secrets" }` |
| `PII_TYPE` | `category`: `"EMAIL"`, `"CREDIT_CARD"`, `"PHONE"`, `"GOVERNMENT_ID"` | `{ type: "PII_TYPE", category: "EMAIL" }` |
| `KEY_MATCH` | `sensitiveKeys` (string[]), `replacement?` (string, default: `"[MASKED_KEY]"`) | `{ type: "KEY_MATCH", sensitiveKeys: ["password"] }` |

---

## Task Rules Reference

### TaskRule

| Field | Type | Description |
|-------|------|-------------|
| `ruleId` | string | Unique rule identifier |
| `eventName` | string | Event to match (see Event Detection Reference) |
| `severity` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"INFO"` | Minimum severity threshold. Rule fires only when actual severity >= this value. |
| `actionType` | string | Action to take (see below) |
| `executionLevel` | string | Automation level (see below) |
| `priority` | 1-5 | Priority (1 = highest). Tasks sorted by priority ascending. |
| `description` | string | Human-readable description |
| `executionParams` | object | Action-specific parameters |
| `guardrails` | object | Safety constraints |

### Action Types

| Action | Description |
|--------|-------------|
| `AI_ANALYZE` | Trigger AI analysis of the event |
| `AUTOMATED_REMEDIATE` | Execute automated fix (Go server: fails without handler) |
| `SYSTEM_NOTIFICATION` | Send notification (Slack, email, etc.) |
| `EXTERNAL_WEBHOOK` | Call external webhook |
| `KILL_SWITCH` | Emergency shutdown action (Go server: fails without handler) |
| `ESCALATE` | Escalate to human for review |

### Execution Levels

| Level | Behavior |
|-------|----------|
| `AUTO` | Dispatch immediately to handler |
| `SEMI_AUTO` | Dispatch unless `requireHumanApproval` is set |
| `MANUAL` | Always require human approval (`blocked_approval`) |
| `MONITOR` | Skip execution, observation only (`skipped`) |

### Guardrails

| Field | Type | Description |
|-------|------|-------------|
| `requireHumanApproval` | boolean | If true, task is always blocked regardless of execution level |
| `timeoutMs` | number | Handler execution timeout (for future use) |
| `maxRetries` | number | Max retry count on handler failure (for future use) |

### Example Rules

```typescript
taskRules: [
  // Critical failure → immediate Slack notification
  {
    ruleId: "crit-slack",
    eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "HIGH",
    actionType: "SYSTEM_NOTIFICATION",
    executionLevel: "AUTO",
    priority: 1,
    description: "Slack alert for critical failures",
    executionParams: { notificationChannel: "#incidents" },
    guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
  },
  // Security intrusion → AI analysis
  {
    ruleId: "sec-ai",
    eventName: "SECURITY_INTRUSION_DETECTED",
    severity: "HIGH",
    actionType: "AI_ANALYZE",
    executionLevel: "AUTO",
    priority: 1,
    description: "AI-powered intrusion analysis",
    executionParams: {},
    guardrails: { requireHumanApproval: false, timeoutMs: 60000, maxRetries: 2 },
  },
  // Compliance violation → manual escalation
  {
    ruleId: "comp-escalate",
    eventName: "COMPLIANCE_VIOLATION",
    severity: "MEDIUM",
    actionType: "ESCALATE",
    executionLevel: "MANUAL",
    priority: 1,
    description: "Escalate to legal team",
    executionParams: { notificationChannel: "#legal" },
    guardrails: { requireHumanApproval: true, timeoutMs: 86400000, maxRetries: 0 },
  },
]
```

---

## Event Detection Reference

### Built-in Detection Rules

| Event | Trigger Condition | Priority | Payload Type |
|-------|------------------|----------|--------------|
| `SYSTEM_CRITICAL_FAILURE` | `isCritical == true` | HIGH | `{ component, errorDetails }` |
| `SECURITY_INTRUSION_DETECTED` | `type == "SECURITY" && level >= 5` | HIGH | `{ ip, severity }` |
| `COMPLIANCE_VIOLATION` | `type == "COMPLIANCE" && message contains "violation"` | HIGH | `{ ruleId, documentId, userId }` |
| `SYSTEM_CRITICAL_FAILURE` | `type == "SLA" && level >= 4` | MEDIUM | `{ component, errorDetails }` |

### AI Loop Prevention

Logs with `origin: "AI_AGENT"` are not evaluated by the detector unless `isCritical: true`. This prevents infinite detection loops when AI agents generate logs that would trigger further AI tasks.

### Severity Classification

The TaskGenerator classifies severity from the detection result and log context:

| Condition | Assigned Severity |
|-----------|-------------------|
| `isCritical == true` | CRITICAL |
| `SECURITY_INTRUSION_DETECTED` + level 6 | CRITICAL |
| `SECURITY_INTRUSION_DETECTED` + level 5 | HIGH |
| `SYSTEM_CRITICAL_FAILURE` + HIGH priority | CRITICAL |
| `SYSTEM_CRITICAL_FAILURE` + MEDIUM priority | HIGH |
| `COMPLIANCE_VIOLATION` | HIGH |
| `AI_ACTION_REQUIRED` | MEDIUM |
| Fallback: level 6 | CRITICAL |
| Fallback: level 5 | HIGH |
| Fallback: level 4 | MEDIUM |
| Fallback: level 3 | LOW |
| Fallback: level 1-2 | INFO |

### Log Types

| Type | Description |
|------|-------------|
| `SYSTEM` | General system logs (default) |
| `SECURITY` | Security events (login, access control, intrusion) |
| `COMPLIANCE` | Regulatory compliance events |
| `BUSINESS-AUDIT` | Business transaction audit trail |
| `INFRA` | Infrastructure events |
| `SLA` | Service level agreement monitoring |
| `DEBUG` | Debug information (not evaluated for events) |

### Log Levels

| Level | Name | Detection Trigger |
|-------|------|-------------------|
| 1 | Trace | None |
| 2 | Debug | None |
| 3 | Info | None (default) |
| 4 | Warn | SLA violation (with type=SLA) |
| 5 | Error | Security intrusion (with type=SECURITY) |
| 6 | Critical | Security intrusion (with type=SECURITY) |

---

## v2 新機能

### カスタム検知ルール（detectionRules）

組込みの5ルールに加えて、独自のパターンマッチ検知ルールを追加可能。

```typescript
const sentinel = Sentinel.initialize(createDefaultConfig({
    projectName: "my-app", serviceId: "api",
    detectionRules: [
        {
            ruleId: "brute-force",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                logTypes: ["SECURITY"],
                minLevel: 4,
                messagePattern: /failed.*login|brute.*force/i,
            },
        },
    ],
}));
```

条件はAND結合。`logTypes`, `minLevel`, `maxLevel`, `messagePattern`, `tagMatch`, `origin`, `isCritical` が利用可能。

### ホワイトリスト検証（whitelist）

設定値の妥当性を初期化時に検証。タイポによる無言のルール不発を防止。

```typescript
whitelist: {
    level: "strict",      // strict/standard/permissive/off
    enabledDomains: ["security", "task", "privacy"],
    extensions: {
        actionType: ["CUSTOM_JIRA_TICKET"],
        eventName: ["CUSTOM_BUSINESS_EVENT"],
    },
},
```

| レベル | 挙動 |
|--------|------|
| `strict` | 組込み値のみ許可、extensions無視 |
| `standard` | 組込み値 + extensions、不正値はエラー（デフォルト） |
| `permissive` | 不正値は警告のみ（移行期用） |
| `off` | 検証なし（開発用） |

### メトリクスフック（metrics）

パイプラインの各ステージで呼ばれるオプショナルコールバック。未設定時ゼロオーバーヘッド。

```typescript
metrics: {
    onIngest: () => { counter.inc("logs_ingested"); },
    onDetection: (det) => { counter.inc("events_detected", { event: det.eventName }); },
    onTaskDispatch: (result) => { counter.inc("tasks_dispatched"); },
},
```

### トレーシングフック（tracer）

OpenTelemetry等の分散トレーシングとの統合ポイント。

```typescript
tracer: {
    onPipelineStart: (ctx) => { span = tracer.startSpan(ctx.operation); },
    onPipelineEnd: (ctx) => { span.end(); record(ctx.durationMs); },
},
```

### エラールーティング（errorRouting）

エラーを分類→ルーティング→外部サービス送信。CRITICAL→タスク生成+通知+監査ログ。

```typescript
import { ConsoleAuditSink } from "@sentinel/client";

errorRouting: {
    enabled: true,
    sinks: { audit: new ConsoleAuditSink() },
    onTaskRequest: (req) => { /* タスク生成ロジック */ },
    onNotification: (err, decision) => { /* 通知送信 */ },
},
```

### 動的コールバック更新（updateCallbacks）

初期化後にコールバックを差し替え可能。

```typescript
sentinel.updateCallbacks({
    onLogProcessed: newHandler,   // 差し替え
    onTaskGenerated: null,         // クリア
});
```

### ハンドラのdispose

`onTaskAction()` は解除関数を返す。

```typescript
const dispose = sentinel.onTaskAction("ESCALATE", handler);
// 後で解除
dispose();
```

### YAML設定ファイル（config-loader）

YAMLファイルからSentinelConfigを読み込み可能。

```typescript
import { loadConfigFromYaml, parseConfigYaml } from "@sentinel/client";

// File-based loading
const config = loadConfigFromYaml("./sentinel.config.yaml");
const sentinel = Sentinel.initialize(config);

// String-based parsing with options
const config2 = parseConfigYaml(yamlString, {
  expandEnv: true,              // Enable ${VAR} expansion (default: true)
  strictEnvExpansion: true,     // Throw on undefined vars without defaults (default: false)
  envSource: process.env,       // Custom env source (for testing)
});
```

> **Production tip:** `strictEnvExpansion: true` を使うと、`${API_KEY}` のような必須環境変数の設定漏れをデプロイ前に検出できます。

### gRPC認証（Go Server）

SDK→Server通信にはAPI keyをgRPCメタデータに設定。

```typescript
// SDK側: gRPC transport にAPI key設定
const transport = createGrpcTransport({
    address: "localhost:50051",
    metadata: { "x-api-key": "your-api-key-here" },
});
```

サーバ側: `SENTINEL_API_KEYS=key1,key2` 環境変数、または `auth.api_keys` YAML設定。
