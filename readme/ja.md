# Sentinel

**ログから脅威を検知し、自動で対応する。**

> **重要:** 本プロジェクトはログベースの脅威検知・自動対応のリファレンス実装です。本番環境で使用する前に、実装の詳細を十分にレビューし、ユースケースに合わせて設定を調整し、独自のセキュリティ監査を実施してください。デフォルトの設定・検知ルール・対応戦略は出発点であり、そのまま本番利用するためのものではありません。必ず実際のワークロードでテストし、マスキング・認可・レスポンスの動作が要件を満たしていることを確認してください。

Sentinel はアプリケーションログを監視し、セキュリティ脅威やシステム障害を検知して、通知からAI分析・自動修復まで多段階の対応アクションを自動実行します。

```
アプリログ → Sentinel 検知 → 自動対応

例1: ブルートフォース攻撃
  → IPブロック + Slack #security 通知 + 監査ログ記録

例2: システム障害
  → AIエージェントが原因分析 + 自動修復 + オンコール担当にエスカレーション

例3: コンプライアンス違反
  → 人間の承認を要求 → コンプライアンスチーム通知 → 監査証跡
```

**対応アクション:** AI分析、自動修復、IPブロック、アカウントロック、キルスイッチ、Webhook連携、Slack/Discord/Gmail通知、多段階承認ワークフロー、エスカレーションチェーン。

[アーキテクチャ](../docs/architecture.md) | [セキュリティ](../docs/security.md) | [使い方ガイド](../docs/usage-guide.md) | [English](en(default).md)

---

## コンポーネント

- **TypeScript SDK** — ゼロ依存のクライアントライブラリ。PIIマスキング、ハッシュチェーン整合性、検知ルール、タスク生成。単体（Local Mode）またはGoサーバ連携（Remote/Dual Mode）で動作。
- **Go Server** — gRPCバックエンド。SQLite/SQLCipher永続化、RBAC認可、アンサンブル検知、異常検知、脅威レスポンスオーケストレーション（ブロック/分析/通知）、AIエージェント連携、承認ワークフロー、マルチチャネル通知（Slack/Discord/Gmail/Webhook）を搭載。

## 主要機能

### SDK（TypeScript）
- **カスタム検知ルール** — logType、level、messagePattern、タグによるパターンマッチ検知を設定で定義
- **ホワイトリスト検証** — 4段階のセキュリティレベル: strict / standard / permissive / off
- **PIIマスキング** — 8種のPIIカテゴリ + REGEX + KEY_MATCH、再帰的depth保護付き
- **ハッシュチェーン** — SHA-256整合性チェーン（signingKeyId対応）
- **エラールーティング** — 分類 → ルーティング → 実行（監査sink、デッドレター、タスク、通知）
- **メトリクス・トレーシングフック** — OpenTelemetry / Datadog / カスタムバックエンド向けゼロオーバーヘッドDI
- **ゼロ依存** — サプライチェーン攻撃のリスクゼロ

### サーバ（Go）
- **アンサンブル検知** — マルチルールスコアリング + 異常検知
- **脅威レスポンス** — BLOCK_AND_NOTIFY / ANALYZE_AND_NOTIFY / NOTIFY_ONLY 戦略
- **mTLS** — クライアント証明書検証 + SIGHUPベースの証明書ホットリロード
- **RBAC** — ロールベースアクセス制御（admin/writer/viewer/restricted）
- **承認ワークフロー** — コンテンツハッシュ検証付きマルチステップ承認
- **通知アダプタ** — Slack、Discord、Gmail、Webhook（HMAC署名付き）

## クイックスタート

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
  console.log(`アラート: ${task.description}`);
});

await sentinel.ingest({
  message: "10.0.0.99 からのブルートフォース攻撃検知",
  type: "SECURITY",
  level: 5,
});

await sentinel.shutdown();
```

## 実装状況

**完全動作:** ログパイプライン、PIIマスキング、ハッシュチェーン、検知（単体/アンサンブル/異常）、IPブロック、アカウントロック、通知（Slack/Discord/Gmail/Webhook）、RBAC、承認ワークフロー、mTLS、タスク永続化。

**モック/プレースホルダ:** AI_ANALYZE（MockProvider）、脅威分析（MockAnalysisAgent）、AUTOMATED_REMEDIATE、KILL_SWITCH、ESCALATE、EXTERNAL_WEBHOOK（定数定義済み、ハンドラ未配線）。

**拡張設計:** カスタムアクションハンドラ、検知ルール、通知チャネル、ブロックアクション、AIプロバイダをインターフェース経由でプラグイン可能。詳細は[拡張性ガイド](../packages/server/docs/extensibility-guide.md)を参照。

## テスト状況

| コンポーネント | 技術 | 状態 | テスト |
|--------------|------|------|--------|
| Client SDK | TypeScript（ゼロ依存） | 実装済み | 3,038+ テスト |
| Backend Server | Go 1.22+ / gRPC | 実装済み | 786 テスト |

**合計: 3,824+ テスト、0 FAIL**

## ドキュメント

全ドキュメントへのリンクと詳細な実装状況は[メインREADME](../README.md)を参照。

## ライセンス

リポジトリルートを参照。
