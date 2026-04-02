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
| `security.hmac_key` | (env) | SDK/Server共通HMAC鍵。未設定時SDKはSHA-256フォールバック |
| `security.enable_masking` | true | Server 側 PII マスキング |
| `integration.config_validation` | true | SDK起動時の設定整合性チェック |
| `integration.threat_response_enabled` | false | IngestResponse の threatResponses を SDK に返す |
| `integration.task_approval_enabled` | false | タスク承認フロー (ApproveTask/RejectTask) |
| `integration.task_status_enabled` | false | タスク状態クエリ (GetTaskStatus/ListTasks) |
| `integration.sync_detection_rules` | false | 検知ルール同期 |
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
| 脅威レスポンス | ✅ 接続済み | IngestionResult.threatResponses + onThreatResponse (#4) |
| 検知ルール同期 | ✅ 接続済み | dual-mode ruleId dedup + Server task merge (#5) |
| タスク承認フロー | ✅ 接続済み | ServerManagementTransport 7メソッド (#6) |
| タスク状態管理 | ✅ 接続済み | getTaskStatus/listTasks (#7) |
| ハッシュ方式統一 | ✅ 接続済み | HMAC-SHA256 モード追加、SHA-256 フォールバック (#2) |
| 設定整合性検証 | ✅ 接続済み | HealthCheck ConfigSummary (#3) |
| projectName 送信 | ✅ 接続済み | IngestRequest.project_name フィールド追加 |

## 参照

- 作業計画: [fix-log/2026-04-02-sdk-server-integration-plan.md](fix-log/2026-04-02-sdk-server-integration-plan.md)
- Proto 定義: [packages/server/proto/sentinel.proto](../packages/server/proto/sentinel.proto)
- Server 設定: [packages/server/config/sentinel.yaml](../packages/server/config/sentinel.yaml)
- E2E テスト: [tests/e2e/sdk-server.test.ts](../tests/e2e/sdk-server.test.ts)
- E2E 設定マトリクス: [tests/e2e/server-config-matrix.test.ts](../tests/e2e/server-config-matrix.test.ts)
