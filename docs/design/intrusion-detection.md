# 不正アクセス検知設計

```yaml
created_at: "2026-04-01"
status: implemented (方針A), deferred to Go server (方針B)
branch: feat/configurable-detection-rules
```

## 背景

現状の `EventDetector` は5つのハードコードされた検知ルールを持つ。利用者がカスタム検知ルールを追加する手段がなく、不正アクセスパターンの検知が限定的。

## 方針A: 設定可能なルールベース検知 ✅ 実装済み

### 概要

`SentinelConfig.detectionRules` でカスタム検知ルールを定義可能にする。各ルールは条件（ログタイプ、レベル、メッセージパターン等）とアクション（イベント生成）を定義する。ステートレスで副作用なし。

### 設定例

```typescript
const config = createDefaultConfig({
  projectName: "my-app",
  serviceId: "api-server",
  detectionRules: [
    {
      ruleId: "brute-force-login",
      eventName: "SECURITY_INTRUSION_DETECTED",
      priority: "HIGH",
      conditions: {
        logTypes: ["SECURITY"],
        minLevel: 4,
        messagePattern: /failed.*login|authentication.*failed/i,
        tagMatch: { key: "action", value: "login" },
      },
    },
    {
      ruleId: "unauthorized-api-access",
      eventName: "SECURITY_INTRUSION_DETECTED",
      priority: "HIGH",
      conditions: {
        logTypes: ["SECURITY"],
        minLevel: 3,
        messagePattern: /unauthorized|forbidden|403/i,
      },
    },
    {
      ruleId: "data-export-anomaly",
      eventName: "COMPLIANCE_VIOLATION",
      priority: "MEDIUM",
      conditions: {
        logTypes: ["BUSINESS-AUDIT", "COMPLIANCE"],
        minLevel: 3,
        messagePattern: /export|download|bulk.*access/i,
      },
    },
  ],
});
```

### アーキテクチャ

```
EventDetector
├── Built-in rules (5 hardcoded, always active, 最優先)
│   ├── 1. isCritical → SYSTEM_CRITICAL_FAILURE
│   ├── 2. SECURITY + level≥5 → SECURITY_INTRUSION_DETECTED
│   ├── 3. COMPLIANCE + "violation" → COMPLIANCE_VIOLATION
│   ├── 4. triggerAgent + level≥4 → AI_ACTION_REQUIRED
│   └── 5. SLA + level≥4 → SYSTEM_CRITICAL_FAILURE
│
└── Custom rules (config-driven, 設定順で評価)
    ├── 条件: logTypes, minLevel, maxLevel, messagePattern, tagMatch, origin, isCritical
    ├── 全条件はAND結合
    └── 最初にマッチしたルールが勝つ（built-in優先）
```

### 型定義

```typescript
interface DetectionRule {
  ruleId: string;
  eventName: SystemEventName;
  priority: "HIGH" | "MEDIUM" | "LOW";
  conditions: DetectionRuleConditions;
}

interface DetectionRuleConditions {
  logTypes?: string[];           // いずれかにマッチ（OR）
  minLevel?: number;             // 以上
  maxLevel?: number;             // 以下
  messagePattern?: RegExp;       // メッセージにマッチ
  tagMatch?: { key: string; value?: string }; // タグの存在/値マッチ
  origin?: string;               // originフィルタ
  isCritical?: boolean;          // criticalフラグフィルタ
}
```

### テストカバレッジ

22テスト:
- **正常系 (7)**: messagePattern, tagMatch, logType, minLevel, maxLevel, AND条件, 優先順位
- **異常系 (3)**: 空conditions, ルールなし, undefinedルール
- **エッジケース (5)**: tagMatch key-only, 正規表現特殊文字, origin, isCritical, 50ルールパフォーマンス
- **パイプライン統合 (4)**: タスク生成、不一致、複数ルール、不発確認
- **ペネトレーション (3)**: ReDoS, 空regex, prototype pollution

---

## 方針B: ステートフル行動検知 → Go Server責務

### 判断理由

TS SDKに行動ベース検知を実装すべきでない理由:

1. **ステート管理**: SDKはステートレスであるべき（hash chain以外）。時系列状態の保持はサーバ責務。
2. **横断集計不可**: 複数クライアントからのイベント集計はシングルプロセスSDKでは不可能。ブルートフォース検知（N回失敗/M秒）は全クライアントの視点が必要。
3. **既に実装済み**: Go側に `internal/detection/anomaly.go`（統計的異常検知）、`ensemble.go`（アンサンブル検知）、`dedup.go`（重複抑制）が存在。

### SDK側の責務

- **ルールベース検知（方針A）**: ログ1件ごとの静的パターンマッチング。ステートレス。
- **ログの質**: 正確なtimestamp, actorId, tags をログに含めることで、サーバ側の行動検知の精度を向上させる。
- **イベント伝達**: 検知されたイベントをGoサーバに送信し、サーバ側で行動パターン集計を行う。
