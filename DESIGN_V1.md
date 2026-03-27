# Sentinel V1 MVP - Design Context

## Scope: TypeScript Client SDK (`@sentinel/client`)

The backend server will migrate to **Go**. This v1 focuses on the **client-side SDK** only.

## Core Value Proposition

**Log -> Task Auto-generation -> Action Dispatch**

Sentinel's unique differentiator: converting logs into actionable tasks automatically.

## V1 Pipeline (no WAL, no Worker Pool)

```
Logger.ingest(partialLog)
  -> LogNormalizer.normalize()      // validation + defaults
  -> MaskingService.mask()          // PII protection
  -> IntegritySigner.chain()        // hash-chain (in-memory)
  -> EventDetector.detect()         // pattern matching
  -> TaskGenerator.generate()       // rule-based task generation (CORE)
  -> TaskExecutor.dispatch()        // action dispatch (CORE)
  -> emit to registered handlers    // callback/event-based output
```

## Components IN v1

| Component | Path | Responsibility |
|-----------|------|----------------|
| Logger | src/index.ts | Public API, singleton |
| LogNormalizer | src/core/engine/log-normalizer.ts | Validate + enrich |
| MaskingService | src/security/masking-service.ts | PII redaction |
| IntegritySigner | src/security/integrity-signer.ts | Hash-chain |
| EventDetector | src/core/detection/event-detector.ts | Pattern matching |
| TaskGenerator | src/core/task/task-generator.ts | **NEW** Rule-based task gen |
| SeverityClassifier | src/core/task/severity-classifier.ts | **NEW** Severity mapping |
| TaskExecutor | src/core/task/task-executor.ts | **NEW** Action dispatch |
| Result<T,E> | src/shared/functional/result.ts | Error handling |
| Config types | src/configs/ | Configuration |
| Type defs | src/types/ | Log, Task, Event types |

## Components REMOVED from v1 (server-side / Go migration)

- WAL (wal-manager, file-lock, atomic-file, wal-mapper, protobuf)
- Worker Pool / Worker Threads
- External Transports (CloudWatch, Datadog, HTTP)
- SQL Task Repository
- OpenAI Agent Provider
- DI Container (simplified)

## Architecture Decisions

1. **No WAL**: Persistence is a server-side (Go) concern
2. **No Worker Threads**: Processing is synchronous in the client SDK
3. **In-memory hash-chain**: Integrity verification without disk I/O
4. **Callback-based output**: Consumers register handlers for processed logs/tasks
5. **Rule engine is in-memory**: Task rules loaded at init, matched synchronously
