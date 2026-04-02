# アクションハンドラ実装計画

```yaml
created_at: "2026-04-02T21:00:00Z"
status: done
scope: 5 action handlers + reIngest wiring
```

## 目的

定数だけ定義されていた5つのアクションタイプを実装し、YAML設定から連携して動作するようにする。

## 実装対象

| # | アクション | 現状 | 実装内容 |
|---|---|---|---|
| 1 | ESCALATE | 定数のみ | MultiNotifier に高優先度で送信 |
| 2 | SYSTEM_NOTIFICATION | 定数のみ | MultiNotifier に通知送信 |
| 3 | EXTERNAL_WEBHOOK | 定数のみ | targetEndpoint に JSON POST |
| 4 | KILL_SWITCH | 定数のみ | Pipeline に killed フラグ設定、自動回復 |
| 5 | reIngest ループ | no-op | Pipeline.Process に実接続 |

## 設計判断

### ファイル構成

新規ファイル1つ + 既存ファイル修正:

- **新規**: `task/handlers.go` — 4つのハンドラファクトリ関数
- **修正**: `engine/pipeline.go` — killed フラグ追加
- **修正**: `agent/executor.go` — SetReIngest メソッド追加
- **修正**: `config/config.go` — KillSwitchConfig 追加
- **修正**: `cmd/server/main.go` — ハンドラ登録 + MultiNotifier 再構成 + reIngest 配線

### YAML 設定

既存の `exec_params` フィールドを活用（新規トップレベルセクション不要）:

```yaml
pipeline:
  rules:
    - rule_id: escalate-security
      event_name: SECURITY_INTRUSION_DETECTED
      action_type: ESCALATE                    # ← これが動くようになる
      exec_params:
        notification_channel: "#security-critical"

    - rule_id: webhook-alert
      event_name: SYSTEM_CRITICAL_FAILURE
      action_type: EXTERNAL_WEBHOOK
      exec_params:
        target_endpoint: "https://ops.example.com/webhook"

    - rule_id: emergency-stop
      event_name: SYSTEM_CRITICAL_FAILURE
      action_type: KILL_SWITCH
      execution_level: MANUAL                  # 人間の承認が必要
      guardrails:
        require_human_approval: true

# KILL_SWITCH 自動回復（新規）
kill_switch:
  auto_recovery_timeout_sec: 300  # 5分後に自動回復、0=手動のみ
```

### reIngest ループ防止

AgentBridge に既にループ検知がある（MaxLoopDepth=5）。安全な理由:

1. reIngest されるログは `TriggerAgent: false` → エージェント再起動しない
2. 仮に再検知 → AI_ANALYZE タスク生成 → AgentBridge が LoopDepth チェック → MaxLoopDepth 超過で拒否
3. Pipeline.Process は通常通り処理（マスク・永続化・検知）するが、ループしない

**循環依存の解消**: AgentExecutor に `SetReIngest(fn)` を追加し、sentinel 作成後にコールバックを設定。

### KILL_SWITCH の動作

1. Pipeline.Process() の先頭で `killed` atomic.Bool をチェック
2. true なら `codes.Unavailable` エラーを返す（gRPC 側で変換）
3. HealthCheck は引き続き応答（監視システムが死活確認できるよう）
4. `auto_recovery_timeout_sec > 0` なら time.AfterFunc で自動回復
5. デフォルトは MANUAL 実行レベル（人間の承認が必要）

### EXTERNAL_WEBHOOK のセキュリティ

- `notify.ValidateWebhookURL()` で URL を検証（既存のバリデーション再利用）
- HTTPS のみ許可（本番環境）
- タイムアウト: 10秒
- レスポンスボディは読み捨て（DDoS 防止）

## リスクと対策

| リスク | 対策 |
|---|---|
| reIngest 無限ループ | MaxLoopDepth=5 + TriggerAgent=false + 統合テスト |
| KILL_SWITCH 誤発動 | デフォルト MANUAL（人間承認必要）+ 自動回復タイマー |
| EXTERNAL_WEBHOOK 悪意ある URL | ValidateWebhookURL + HTTPS only + タイムアウト |
| MultiNotifier が response.enabled=false 時に未構築 | MultiNotifier 構築を response ブロックの外に移動 |
| ハンドラ panic でサーバクラッシュ | recover() を各ハンドラに追加 |

## テスト計画

### Go ユニットテスト

- `task/handlers_test.go` — 4ハンドラ各テスト
- `engine/pipeline_test.go` — Kill/Unkill/IsKilled テスト
- `agent/executor_test.go` — SetReIngest テスト

### E2E テスト（server-config-matrix.test.ts に追加）

- [x] ESCALATE: タスクルール設定 → ログ投入 → dispatched 確認
- [x] SYSTEM_NOTIFICATION: 同上
- [x] KILL_SWITCH: ログ投入 → kill_switch 発火 → 次の Ingest が拒否される → 3秒後自動回復 → 再び受付確認

### テストカバレッジの限界（本番投入前に要実環境テスト）

| 項目 | 理由 | 本番での確認方法 |
|---|---|---|
| EXTERNAL_WEBHOOK の実 HTTP 送信 | ValidateWebhookURL が loopback/プライベートIP を拒否するため、E2E テスト環境（localhost）では実リクエストが送れない。Go ユニットテストでもhttptest.TLSServer は 127.0.0.1 なので同様 | 実際の外部 webhook エンドポイント（HTTPS, パブリックIP）でテスト |
| Slack/Discord/Gmail の実送信 | テスト環境にクレデンシャルがない。LogNotifier（ログ出力）がフォールバックとして動作している | 実 webhook URL / SMTP 設定を入れて通知到達を確認 |
| reIngest の AI 分析→再投入フロー | AI プロバイダが MockProvider（固定レスポンス）のため、実際の分析内容に基づく再投入は模擬的 | 実 LLM プロバイダ（OpenAI/Anthropic）を接続してフロー全体を確認 |
| EXTERNAL_WEBHOOK リダイレクト防止 | CheckRedirect のコードは実装済みだが、実際にリダイレクトするサーバでの E2E テストは未実施 | ステージング環境でリダイレクト→ブロック動作を確認 |

## 拡張の可能性

- **AUTOMATED_REMEDIATE**: 同じ handler パターンで将来実装可能。exec_params.script_identifier でスクリプト指定。
- **カスタムアクション**: whitelist extensions で任意の ActionType を登録可能（SDK 側は実装済み）。
- **クラウドブロック**: BlockAction インターフェースに AWS/GCP/Azure 実装を追加するだけ。
- **実 AI プロバイダ**: agent.Provider インターフェースに OpenAI/Anthropic 実装を追加するだけ。
