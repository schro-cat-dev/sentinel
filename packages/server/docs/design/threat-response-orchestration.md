# Threat Response Orchestration — 設計仕様書

## 概要

検知された脅威に対する即座のブロック・分析・通知を、設定ベースの戦略パターンで制御する。
Sentinel サーバ構築時（DI時点）にレスポンス戦略を設定として受け取り、検知イベントに応じて
自動的にブロック/分析/通知を実行する。

## 実装状態

| コンポーネント | 状態 | テスト数 |
|---|---|---|
| ThreatResponseOrchestrator | 実装済み + main.go ワイヤリング済み | 16 |
| BlockDispatcher + IPBlock/AccountLock | 実装済み | 18 |
| EnhancedBlockDispatcher (承認待ち) | 実装済み | 12 |
| AnalysisAgent (Mock) | 実装済み | 6 |
| AWS/GCP/Azure BlockAction | アダプタI/F実装済み | 6 |
| Store永続化 (ThreatResponseStoreRecord) | 実装済み | 3 |
| Proto定義 (ThreatResponseSummary) | 定義済み（pb.go再生成待ち） | - |

## 責務分離

```
Pipeline.Process()
  ├── Detection (ensemble/anomaly)
  │     ↓ []*DetectionResult
  ├── ThreatResponseOrchestrator.Handle()
  │     ├── [1] AnalysisAgent.Analyze()       ← AI分析
  │     ├── [2] BlockDispatcher.Execute()      ← ブロック実行
  │     ├── [3] PersistFunc()                  ← 永続化
  │     └── [4] NotifyFunc()                   ← 通知
  └── TaskGenerator.Generate()                 ← 既存のタスク生成
```

## レスポンス戦略 (ResponseStrategy)

| 戦略 | 分析 | ブロック | 通知 | 用途 |
|---|---|---|---|---|
| `BLOCK_AND_NOTIFY` | Yes | Yes | Yes | セキュリティ侵入の即時対応 |
| `ANALYZE_AND_NOTIFY` | Yes | No | Yes | 分析結果を人に判断させる |
| `NOTIFY_ONLY` | No | No | Yes | 検知のみ通知（デフォルト） |
| `BLOCK_ONLY` | No | Yes | No | サイレント防御 |
| `MONITOR` | No | No | No | ログ記録のみ |

## ブロック実行モード

| モード | 動作 | 用途 |
|---|---|---|
| `IMMEDIATE` | 即座に実行 | 本番環境での自動防御 |
| `REQUIRE_APPROVAL` | 承認待ち → 承認後に実行 | 慎重な判断が必要な場合 |

承認待ちブロックは `EnhancedBlockDispatcher` で管理:
- `ApproveBlock(blockID, approverID)` → 承認後にブロック実行
- `RejectBlock(blockID, rejecterID)` → 却下
- `BlockApprovalStore` I/F で永続化先を差し替え可能

## クラウドプロバイダ連携

`BlockAction` インターフェースを実装すれば任意のクラウドに委任可能:

| アダプタ | 対象サービス | ActionType |
|---|---|---|
| `AWSBlockAction` | Security Group / WAF / GuardDuty | `aws_block` |
| `GCPBlockAction` | Cloud Armor / VPC Firewall Rules | `gcp_block` |
| `AzureBlockAction` | NSG / WAF | `azure_block` |
| `IPBlockAction` | インプロセスIPブロック | `block_ip` |
| `AccountLockAction` | インプロセスアカウントロック | `lock_account` |

各アダプタは `execFn` コールバックでAPI呼び出しを注入する設計。SDK依存なし。

## 通知チャネル

`internal/notify/` パッケージの `Notifier` インターフェースで拡張:

| アダプタ | チャネル | ルーティングプレフィックス |
|---|---|---|
| `SlackNotifier` | Slack Incoming Webhook | `#` |
| `GmailNotifier` | Gmail (SMTP) | `@` |
| `DiscordNotifier` | Discord Webhook | - |
| `WebhookNotifier` | HTTP Webhook (HMAC署名付き) | `https://` |
| `LogNotifier` | stdout（フォールバック） | - |

`MultiNotifier` がプレフィックスベースで自動ルーティング。

## フォールトトレランス

- 分析失敗 → ブロックは続行（テスト済み）
- ブロック失敗 → 通知は続行（テスト済み）
- 通知失敗 → ログ出力、レスポンスは返る（テスト済み）
- 永続化失敗 → ログ出力、処理は続行（テスト済み）
- IP不明 → ブロックは安全にスキップ（テスト済み）

## 設定例

```yaml
response:
  enabled: true
  default_strategy: NOTIFY_ONLY
  block_mode: IMMEDIATE              # IMMEDIATE / REQUIRE_APPROVAL
  rules:
    - event_name: SECURITY_INTRUSION_DETECTED
      strategy: BLOCK_AND_NOTIFY
      block_action: block_ip
      analysis_prompt: "Analyze this security intrusion..."
      notify_targets: ["#security-alerts"]
    - event_name: ANOMALY_DETECTED
      strategy: ANALYZE_AND_NOTIFY
    - event_name: COMPLIANCE_VIOLATION
      strategy: NOTIFY_ONLY
      notify_targets: ["#compliance"]
```

## 環境変数

| 変数 | 説明 |
|---|---|
| `SENTINEL_RESPONSE_ENABLED` | 脅威レスポンス有効化 (`true`/`1`) |
| `SENTINEL_RESPONSE_DEFAULT_STRATEGY` | デフォルト戦略 |
