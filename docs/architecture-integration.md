# SDK ↔ Server 連携アーキテクチャ

```yaml
created_at: "2026-04-02"
status: current
```

## 全体像

```
┌─────────────────────────────────────────────────────────────────────┐
│  TypeScript SDK                                                     │
│                                                                     │
│  ingest(log)                                                        │
│    ├─ validateLogInput()                                            │
│    ├─ normalize() → mask() → detect() → generateTasks()            │
│    ├─ integritySign() (SHA-256 or HMAC-SHA256)                     │
│    ├─ TaskExecutor.dispatch()                                       │
│    │    ├─ onTaskAction handlers (コールバック)                      │
│    │    └─ TaskTransports (HTTP webhook 等)                         │
│    └─ RemoteTransport.send() ──────────────────────────┐           │
│                                                         │           │
│  管理 API (設定駆動)                                     │           │
│    ├─ approveTask() ──────── ServerManagementTransport ─┤           │
│    ├─ rejectTask()                                      │           │
│    ├─ listPendingBlocks()                               │           │
│    ├─ getTaskStatus()                                   │  gRPC     │
│    └─ listTasks()                                       │           │
└─────────────────────────────────────────────────────────┼───────────┘
                                                          │
                                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Go Server (sentinel.yaml 設定駆動)                                 │
│                                                                     │
│  SentinelService (10 RPCs)                                          │
│    ├─ Ingest ─────────────── Pipeline                               │
│    │    ├─ Normalize + Mask                                         │
│    │    ├─ HMAC-SHA256 hash chain verify                            │
│    │    ├─ Detect (static rules + ensemble + anomaly)               │
│    │    ├─ Generate tasks → Store (SQLite)                          │
│    │    ├─ Threat response (block / analyze / notify)               │
│    │    └─ Return IngestResponse                                    │
│    │         ├─ hash_chain_valid                                    │
│    │         ├─ masked                                              │
│    │         ├─ tasks_generated[]                                   │
│    │         └─ threat_responses[]                                  │
│    │                                                                │
│    ├─ HealthCheck ──── status + version (+ config_summary 予定)     │
│    ├─ GetTaskStatus / ListTasks ──── タスク状態クエリ               │
│    ├─ ApproveTask / RejectTask ──── タスク承認ワークフロー          │
│    ├─ ListPendingBlocks / ApproveBlock / RejectBlock ── ブロック管理│
│    └─ GetThreatResponses ──── 脅威レスポンス詳細                    │
│                                                                     │
│  通知 (MultiNotifier)                                               │
│    ├─ Slack (webhook, SSRF防御済)                                   │
│    ├─ Discord (webhook, SSRF防御済)                                 │
│    ├─ Gmail (SMTP)                                                  │
│    └─ Generic Webhook (HMAC署名)                                    │
│                                                                     │
│  認証・認可                                                          │
│    ├─ API Key (x-api-key header, timing-safe比較)                   │
│    ├─ TLS/mTLS (証明書ホットリロード)                               │
│    ├─ RBAC (can_write/read/approve/admin)                           │
│    └─ Rate Limiting (per-client token bucket)                       │
│                                                                     │
│  永続化                                                              │
│    └─ SQLite (WAL) + SQLCipher (暗号化オプション)                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Transport モード別データフロー

### local（デフォルト）

```
SDK: ingest → normalize → mask → detect → tasks → sign → return
Server: 使用しない
```

### remote

```
SDK: ingest → validate → normalizeOnly → mask → send ──→ Server
                                                          ↓
SDK: ← IngestionResult ←──────────────────────── IngestResponse
```

### dual

```
SDK: ingest → handle(local pipeline) ──→ IngestionResult (即座に返却)
                    ↓
              lastProcessedLog
                    ↓
              send(async) ────────→ Server (結果は transportError に記録)
```

## 設定による機能有効化マトリクス

| sentinel.yaml パラメータ | デフォルト | 影響範囲 |
|-------------------------|----------|---------|
| `auth.enabled` | false | API key 認証、レートリミット |
| `security.enable_hash_chain` | true | HMAC-SHA256 チェーン検証 |
| `security.enable_masking` | true | Server 側 PII マスキング |
| `ensemble.enabled` | false | スコアベース動的検知 |
| `anomaly.enabled` | false | 異常検知 |
| `agent.enabled` | false | AI エージェント連携 |
| `response.enabled` | false | 脅威レスポンス (ブロック/通知) |
| `authorization.enabled` | false | RBAC 認可 |
| `notify.slack.enabled` | false | Slack 通知 |
| `notify.discord.enabled` | false | Discord 通知 |
| `notify.gmail.enabled` | false | Gmail 通知 |

## 現在の連携ステータス

| 連携 | ステータス | 備考 |
|------|-----------|------|
| ログ投入 (Ingest) | ✅ 接続済み | E2E テスト確認済み |
| レスポンス受信 | ✅ 接続済み | hashChainValid, masked, tasksGenerated |
| ハッシュチェーン検証 | ✅ 接続済み | Server 側で HMAC 検証 |
| PII マスキング | ✅ 接続済み | SDK + Server 双方で実行 |
| ヘルスチェック | ✅ 接続済み | gRPC HealthCheck |
| 脅威レスポンス | ⚠ Proto定義済み/SDK未消費 | Phase 2 で対応予定 |
| 検知ルール同期 | ⚠ 独立動作 | Phase 2 で対応予定 |
| タスク承認フロー | ⚠ Server RPC 実装済み/SDK未接続 | Phase 3 で対応予定 |
| タスク状態管理 | ⚠ Server RPC 実装済み/SDK未接続 | Phase 3 で対応予定 |
| ハッシュ方式統一 | ⚠ SDK=SHA-256, Server=HMAC-SHA256 | Phase 1 で対応予定 |
| 設定整合性検証 | ❌ 未実装 | Phase 1 で対応予定 |

## 参照

- 作業計画: [fix-log/2026-04-02-sdk-server-integration-plan.md](fix-log/2026-04-02-sdk-server-integration-plan.md)
- Proto 定義: [packages/server/proto/sentinel.proto](../packages/server/proto/sentinel.proto)
- Server 設定: [packages/server/config/sentinel.yaml](../packages/server/config/sentinel.yaml)
- E2E テスト: [tests/e2e/sdk-server.test.ts](../tests/e2e/sdk-server.test.ts)
