# Sentinel

**Detect threats in your logs. Automatically respond.**

> **Important:** This project is a reference implementation for log-based threat detection and automated response. Before using in production, thoroughly review the implementation details, adapt configuration to your specific use case, and conduct your own security audit. The default settings, detection rules, and response strategies are starting points — not production-ready defaults. Always test with your own workloads and verify that masking, authorization, and response behaviors meet your requirements.

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

[Architecture](../docs/architecture.md) | [Security](../docs/security.md) | [Usage Guide](../docs/usage-guide.md) | [日本語](ja.md)

---

## Components

- **TypeScript SDK** — Zero-dependency client library. PII masking, hash-chain integrity, detection rules, and task generation. Works standalone (Local Mode) or with the Go server (Remote/Dual Mode).
- **Go Server** — gRPC backend with SQLite/SQLCipher persistence, RBAC authorization, ensemble detection, anomaly detection, threat response orchestration (block/analyze/notify), and approval workflows with multi-channel notifications (Slack/Discord/Gmail/Webhook).

## Key Features

### SDK (TypeScript)
- **Custom Detection Rules** — Define pattern-based detection via config (logType, level, messagePattern, tags)
- **Whitelist Validation** — 4 security levels: strict / standard / permissive / off
- **PII Masking** — 8 PII categories + REGEX + KEY_MATCH, with recursive depth protection
- **Hash Chain** — SHA-256 integrity chain with signingKeyId support
- **Error Routing** — Classify → Route → Execute (audit sink, dead letter, task, notification)
- **Metrics & Tracing Hooks** — Zero-overhead DI for OpenTelemetry / Datadog / custom backends
- **Zero Dependencies** — No supply chain attack surface

### Server (Go)
- **Ensemble Detection** — Multi-rule scoring with anomaly detection
- **Threat Response** — BLOCK_AND_NOTIFY / ANALYZE_AND_NOTIFY / NOTIFY_ONLY strategies
- **mTLS** — Client certificate verification with SIGHUP-based cert hot-reload
- **RBAC** — Role-based access control (admin/writer/viewer/restricted)
- **Approval Workflows** — Multi-step approval with content hash verification
- **Notification Adapters** — Slack, Discord, Gmail, Webhook with HMAC signing

## Quick Start

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
  detectionRules: [{
    ruleId: "brute-force",
    eventName: "SECURITY_INTRUSION_DETECTED",
    priority: "HIGH",
    conditions: {
      logTypes: ["SECURITY"],
      messagePattern: /failed.*login|brute.*force/i,
    },
  }],
  whitelist: { level: "strict" },
}));

sentinel.onTaskAction("ESCALATE", async (task) => {
  console.log(`Alert: ${task.description}`);
});

await sentinel.ingest({
  message: "Brute force attack from 10.0.0.99",
  type: "SECURITY",
  level: 5,
});

await sentinel.shutdown();
```

## Project Status

| Component | Technology | Status | Tests |
|-----------|-----------|--------|-------|
| Client SDK | TypeScript (zero dependencies) | Implemented | 3,038+ tests |
| Backend Server | Go 1.22+ / gRPC | Implemented | 786 tests |

**Total: 3,824+ tests, 0 FAIL**

## Documentation

See the [main README](../README.md) for full documentation links.

## License

See repository root.
