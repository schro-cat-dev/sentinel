# Sentinel Server — 使い方ガイド

## 目次

1. [インストール・起動](#インストール起動)
2. [設定ファイル詳細](#設定ファイル詳細)
3. [環境変数一覧](#環境変数一覧)
4. [gRPC API リファレンス](#grpc-api-リファレンス)
5. [セキュリティレベル設定](#セキュリティレベル設定)
6. [TypeScript SDK 連携](#typescript-sdk-連携)

---

## インストール・起動

### ビルド

```bash
cd packages/server
go build -o sentinel-server ./cmd/server/
```

### 最小構成で起動

```yaml
# config/sentinel.yaml
pipeline:
  service_id: "my-service"
security:
  enable_hash_chain: true
  hmac_key: "your-secret-key-at-least-32-bytes-long!!"
```

```bash
./sentinel-server -config config/sentinel.yaml
# => server listening on :50051
```

### 全モジュール有効で起動

```bash
export SENTINEL_HMAC_KEY="your-secret-key-at-least-32-bytes-long!!"
export SENTINEL_ENSEMBLE_ENABLED=true
export SENTINEL_ANOMALY_ENABLED=true
export SENTINEL_AGENT_ENABLED=true
export SENTINEL_RESPONSE_ENABLED=true
export SENTINEL_RESPONSE_DEFAULT_STRATEGY=BLOCK_AND_NOTIFY
./sentinel-server -config config/sentinel.yaml
```

---

## 設定ファイル詳細

### pipeline（必須）

```yaml
pipeline:
  service_id: "my-service"        # 必須: サービス識別子
  rules:                          # タスク生成ルール
    - rule_id: "sec-analyze"
      event_name: "SECURITY_INTRUSION_DETECTED"
      severity: "HIGH"            # CRITICAL / HIGH / MEDIUM / LOW / INFO
      action_type: "AI_ANALYZE"   # AI_ANALYZE / AUTOMATED_REMEDIATE / SYSTEM_NOTIFICATION / EXTERNAL_WEBHOOK / KILL_SWITCH / ESCALATE
      execution_level: "AUTO"     # AUTO / SEMI_AUTO / MANUAL / MONITOR
      priority: 1                 # 1=最高
      description: "AI分析を実行"
      exec_params:
        target_endpoint: "https://..."
        notification_channel: "#security"
        prompt_template: "..."
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
```

### security

```yaml
security:
  enable_masking: true            # PIIマスキング有効化
  enable_hash_chain: true         # HMAC-SHA256ハッシュチェーン
  hmac_key: "32bytes..."          # 環境変数 SENTINEL_HMAC_KEY で上書き可
  preserve_fields: ["traceId"]    # マスキング対象外フィールド
  masking_depth_limit: 32         # 再帰マスキング最大深度
  masking_rules:
    - type: "PII_TYPE"            # PII_TYPE / REGEX / KEY_MATCH
      category: "EMAIL"           # EMAIL / PHONE / CREDIT_CARD / GOVERNMENT_ID
    - type: "REGEX"
      pattern: "secret-\\d+"
      replacement: "[REDACTED]"
```

### ensemble（検知拡張）

```yaml
ensemble:
  enabled: true
  aggregator: "max"               # max / avg / weighted_sum
  threshold: 0.5                  # 0.0〜1.0 発火閾値
  dedup_window_sec: 10            # 重複抑制ウィンドウ（秒）
  dynamic_rules:
    - rule_id: "brute-force"
      event_name: "SECURITY_INTRUSION_DETECTED"
      priority: "HIGH"
      score: 0.95
      payload_builder: "security_intrusion"  # security_intrusion / system_critical / compliance_violation
      conditions:
        log_types: ["SECURITY"]
        min_level: 4
        max_level: 6
        message_pattern: "(?i)brute\\s*force"
        tag_keys: ["ip"]
        origins: ["SYSTEM"]
```

### anomaly（異常検知）

```yaml
anomaly:
  enabled: true
  window_size_sec: 60             # 分析ウィンドウ（秒）
  baseline_window_sec: 600        # ベースライン計算ウィンドウ
  threshold_pct: 300.0            # 乖離率閾値（%）
  min_baseline: 3.0               # ベースライン最小値（ノイズ回避）
```

### response（脅威レスポンス）

```yaml
response:
  enabled: true
  default_strategy: "NOTIFY_ONLY"   # BLOCK_AND_NOTIFY / ANALYZE_AND_NOTIFY / NOTIFY_ONLY / BLOCK_ONLY / MONITOR
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"      # block_ip / lock_account
      analysis_prompt: "Analyze this intrusion..."
      notify_targets: ["#security"]
      min_priority: "HIGH"          # この優先度以上のみ適用
```

### authorization（RBAC認可）

```yaml
authorization:
  enabled: true
  default_role: "viewer"
  roles:
    admin:
      can_write: true
      can_read: true
      can_approve: true
      can_admin: true
    writer:
      allowed_log_types: ["SYSTEM", "INFRA", "DEBUG"]
      denied_log_types: ["SECURITY"]
      max_log_level: 5
      can_write: true
      can_read: true
    viewer:
      can_read: true
  client_roles:                     # クライアントID → ロール
    "api-key-admin-001": "admin"
    "api-key-writer-001": "writer"
```

### agent（AIエージェント）

```yaml
agent:
  enabled: true
  provider: "mock"                  # 現在は mock のみ
  max_loop_depth: 5
  timeout_sec: 60
  allowed_actions: ["AI_ANALYZE"]
  min_severity: "HIGH"
```

### auth / webhook / server / store

```yaml
auth:
  enabled: true
  api_keys: ["key-1", "key-2"]     # SENTINEL_API_KEYS で上書き可
  rate_limit_rps: 100
  rate_limit_burst: 200

webhook:
  enabled: true
  url: "https://hooks.example.com/sentinel"
  timeout_sec: 10
  secret: "webhook-hmac-secret"

server:
  addr: ":50051"                    # SENTINEL_ADDR で上書き可
  graceful_timeout_sec: 30

store:
  driver: "sqlite"
  dsn: "file:sentinel.db?_journal=WAL"
```

---

## 環境変数一覧

| 変数 | 説明 | 例 |
|---|---|---|
| `SENTINEL_HMAC_KEY` | HMACキー（32バイト以上） | `my-secret-key...` |
| `SENTINEL_ADDR` | サーバアドレス | `:8080` |
| `SENTINEL_API_KEYS` | APIキー（カンマ区切り） | `key1,key2` |
| `SENTINEL_ENSEMBLE_ENABLED` | アンサンブル検知 | `true` |
| `SENTINEL_ANOMALY_ENABLED` | 異常検知 | `true` |
| `SENTINEL_AGENT_ENABLED` | AIエージェント | `true` |
| `SENTINEL_AGENT_PROVIDER` | AIプロバイダ名 | `mock` |
| `SENTINEL_AUTHZ_ENABLED` | RBAC認可 | `true` |
| `SENTINEL_RESPONSE_ENABLED` | 脅威レスポンス | `true` |
| `SENTINEL_RESPONSE_DEFAULT_STRATEGY` | デフォルト戦略 | `BLOCK_AND_NOTIFY` |
| `SENTINEL_SLACK_WEBHOOK_URL` | Slack通知 | `https://hooks.slack.com/...` |
| `SENTINEL_DISCORD_WEBHOOK_URL` | Discord通知 | `https://discord.com/api/...` |
| `SENTINEL_GMAIL_FROM` | Gmail送信元 | `sentinel@company.com` |
| `SENTINEL_GMAIL_PASSWORD` | Gmailアプリパスワード | `xxxx xxxx xxxx xxxx` |

---

## gRPC API リファレンス

### Ingest（ログ投入）
```protobuf
rpc Ingest(IngestRequest) returns (IngestResponse)
```
ログを投入し、検知・ブロック・タスク生成の結果を返す。

### HealthCheck
```protobuf
rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse)
```

### GetTaskStatus / ListTasks
```protobuf
rpc GetTaskStatus(GetTaskStatusRequest) returns (GetTaskStatusResponse)
rpc ListTasks(ListTasksRequest) returns (ListTasksResponse)
```

### ApproveTask / RejectTask（タスク承認）
```protobuf
rpc ApproveTask(ApproveTaskRequest) returns (ApproveTaskResponse)
rpc RejectTask(RejectTaskRequest) returns (RejectTaskResponse)
```
多段階承認チェーンに対応。内容改ざん検知（ContentHash比較）付き。

### ApproveBlock / RejectBlock（ブロック承認）
```protobuf
rpc ApproveBlock(ApproveBlockRequest) returns (ApproveBlockResponse)
rpc RejectBlock(RejectBlockRequest) returns (RejectBlockResponse)
```
`REQUIRE_APPROVAL` モード時のIPブロック承認/却下。

---

## セキュリティレベル設定

用途に応じた推奨設定:

### 開発環境（最小構成）

```yaml
security:
  enable_masking: false
  enable_hash_chain: false
# ensemble, anomaly, response, authorization: 全て無効（デフォルト）
```

### ステージング環境（検知のみ）

```yaml
security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "staging-key..."
ensemble:
  enabled: true
  threshold: 0.5
anomaly:
  enabled: true
response:
  enabled: true
  default_strategy: "NOTIFY_ONLY"
```

### 本番環境（全機能）

```yaml
security:
  enable_masking: true
  enable_hash_chain: true
ensemble:
  enabled: true
  threshold: 0.7
  dedup_window_sec: 30
anomaly:
  enabled: true
  threshold_pct: 300.0
response:
  enabled: true
  default_strategy: "BLOCK_AND_NOTIFY"
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"
    - event_name: "COMPLIANCE_VIOLATION"
      strategy: "ANALYZE_AND_NOTIFY"
authorization:
  enabled: true
auth:
  enabled: true
agent:
  enabled: true
```

---

## TypeScript SDK 連携

### ローカルのみ（デフォルト）

```typescript
const sentinel = Sentinel.initialize(config);
// SDK内部でパイプライン処理。サーバ不要。
```

### サーバにも送信（dual モード）

```typescript
import { createGrpcTransport } from "./examples/grpc-transport";

const transport = createGrpcTransport("localhost:50051", "my-api-key");
const sentinel = Sentinel.initialize(config, {
  transport: { mode: "dual", transport }
});
// ローカル処理 + サーバ送信の両方を実行
```

### サーバのみ（remote モード）

```typescript
const sentinel = Sentinel.initialize(config, {
  transport: { mode: "remote", transport, fallbackToLocal: true }
});
// サーバに送信。失敗時はローカルにフォールバック。
```
