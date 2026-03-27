# SIEM/XDR連携設計

> **ステータス**: 設計ドラフト。現在の実装ではSIEM/XDR連携は未実装。
> Task Layer（ログ→タスク自動生成）が完成しており、SIEM連携はAction Layerとして後続フェーズで追加予定。

---

## SIEM/XDR連携の位置づけ

SentinelのSIEM/XDR連携は **Action Layer の最終出力** として設計する。

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────────┐
│   Ingestion     │───▶│  Intelligence/   │───▶│   Action Layer + SIEM/XDR   │
│ Proxy+Security  │    │   Task Layer     │    │  (AI/Alert/SIEM/Action)     │
└─────────────────┘    └──────────────────┘    └─────────────────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────────┐
│ HashChain+Store │    │ TaskRepo+Manager  │    │ SIEM(XDR)/PagerDuty/Email   │
│                 │    │+ Severity Filter  │    │ Connector                   │
└─────────────────┘    └──────────────────┘    └─────────────────────────────┘
```

---

## SIEM Connector

| SIEM | プロトコル | エンドポイント |
|------|-----------|---------------|
| Splunk | HEC (HTTP Event Collector) | `POST /services/collector` |
| Elastic | Elasticsearch Bulk API | `POST /sentinel-security/_bulk` |
| Sumologic | HTTP Collector | `POST /api/v2/collector` |
| QRadar | Syslog CEF形式 | `UDP 514` |
| カスタム | Webhook | 設定で指定 |

## XDR Connector

| XDR | 接続方式 |
|-----|---------|
| Microsoft Defender XDR | Sentinel Connector API |
| CrowdStrike Falcon | REST API |
| Palo Alto Cortex XDR | REST API |

## 標準プロトコル対応

```
├── CEF (Common Event Format) → UDP/TCP 514
├── JSON over HTTP → /api/v1/ingest
├── Syslog RFC5424 → UDP/TCP 514
```

---

## TaskRouterでのSIEM連携フロー

```
Task.executionLevel に応じた分岐:
  AUTO       → AIエージェント自動実行 → 結果をSIEMに送信
  SEMI_AUTO  → 承認リクエスト → 承認後にAI実行 → SIEMに送信
  MANUAL     → SIEM/PagerDutyへ全イベント送信 → 人間が対応
  MONITOR    → SIEMへ監視用ログ送信のみ
```

---

## 開発フェーズ

| Phase | 内容 | ステータス |
|-------|------|-----------|
| Phase 1 | Task Layer MVP（SIEMなし） | **完成** |
| Phase 2 | Severity Filter + 承認ワークフロー | **完成** |
| Phase 3 | Action Layer → SIEM/XDRコネクタ実装 | 未着手 |

---

## SIEM連携時のセキュリティ要件

| 要件 | Sentinel対応状況 |
|------|-----------------|
| ハッシュチェーン（改ざん検知） | HMAC-SHA256実装済み |
| エラー分類体系（60+分類） | ErrorLayer/ErrorKind定義済み |
| データ損失防止 | SQLite永続化実装済み |
| トレース相関 | traceId/spanId対応済み |

---

## Action Layer 外部依存一覧

### AI Action

| アクション | 外部API | 内容 |
|-----------|---------|------|
| 根本原因解析 | OpenAI / Claude | ログ+ErrorLayer → 根本原因レポート |
| 脆弱性スキャン | GitHub CodeQL API | 影響コード自動解析 |
| 自動パッチ生成 | GitHub Copilot API | 脆弱性→パッチPR自動作成 |
| 脅威インテル | VirusTotal API | ハッシュ/IP脅威情報取得 |

### 通知・インシデント管理

| システム | アクション |
|---------|-----------|
| Slack | `#emergencies` チャンネル通知 + @oncall |
| PagerDuty | CRITICAL → 即時インシデント作成 |
| Jira | 自動チケット作成 + 担当者割り当て |
| Microsoft Teams | Adaptive Cardで承認依頼 |

### 自動修復

| アクション | 外部ツール |
|-----------|-----------|
| DBフェイルオーバー | `docker restart db-replica-01` |
| Circuit Breaker | Redis TTL設定変更 |
| レートリミット調整 | NGINX `limit_req_zone` 動的変更 |
| コンテナ再起動 | Kubernetes `kubectl rollout restart` |
