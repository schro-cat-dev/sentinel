# Sentinel Server v2 Design

## Implementation Phases

| Phase | Content | Dependencies |
|-------|---------|-------------|
| 1 | Config (YAML) + Store interface + SQLite | go.mod additions |
| 2 | Domain model expansion (AI fields, approval lifecycle) | Phase 1 |
| 3 | Proto v2 + codegen | Phase 2 |
| 4 | Deep masking + Japan PII | None |
| 5 | Auth interceptor + Rate limiter + Webhook | Phase 1 |
| 6 | Pipeline integration (Store, DeepMasker, Webhook) | Phase 1-5 |
| 7 | gRPC new RPCs (GetTaskStatus, ListTasks, ApproveTask, RejectTask) | Phase 2,3,6 |
| 8 | main.go rewrite + integration tests | All |

## Database Schema

All tables are append-only or update-restricted.
- logs: immutable after insert
- tasks: only status + error_message transitions
- approval_requests: only resolution (once)
- task_results: append-only

## Task Status Lifecycle

```
pending → dispatched → completed
pending → dispatched → failed
pending → blocked_approval → approved → dispatched → completed/failed
pending → blocked_approval → rejected
pending → skipped
```

## SEMI_AUTO Behavior Change (v1 → v2)

v1: SEMI_AUTO dispatched immediately
v2: SEMI_AUTO creates approval request (requires ApproveTask RPC)
