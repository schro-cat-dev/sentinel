# TaskTransport アダプタパターン設計

> **ステータス**: 設計確定 — 実装開始
> **Date**: 2026-04-02

---

## 1. 背景と課題

現在のタスクディスパッチは **コールバック方式のみ** (`onTaskAction` ハンドラ)。
ユーザーはSlack/HTTP/Jira等の連携を全て自前で実装する必要がある。

**要件**:
- 外部システムへのタスク配信を **アダプタパターン** で抽象化する
- 複数のトランスポートを同時に使用可能にする（Slack + Jira 等）
- YAML設定からトランスポートを参照・構成できるようにする
- 既存の `onTaskAction` コールバック方式と **共存** する（破壊的変更なし）
- `RemoteTransport`（ログ送信用）と同じ設計思想に揃える

---

## 2. 設計方針

### 2.1 やること

| 項目 | 内容 |
|------|------|
| `TaskTransport` インターフェース | `dispatch(task) → TaskTransportResult` |
| `TaskExecutor` 統合 | ハンドラ実行後にトランスポートも実行 |
| `SentinelConfig.taskTransports` | 設定への追加 |
| YAML `task_transports` | config-loader での snake_case 対応 |
| 公開 API エクスポート | `index.ts` から型をエクスポート |

### 2.2 やらないこと（と理由）

| 項目 | 理由 |
|------|------|
| 組み込みHTTP/Slack/Jiraアダプタ | zero-dep方針。利用者が `TaskTransport` を実装して注入する |
| タスクキュー/バッチング | 現時点ではスコープ外。トランスポート実装側でバッファリング可能 |
| タスクライフサイクル追跡 | Goサーバ側の責務。SDKは dispatch + result のみ |
| actionType → transport のルーティング | 全トランスポートが全タスクを受け取る。フィルタリングはトランスポート実装側の責務 |

### 2.3 拡張ポリシー

**差し替え可能にすべき部分**:
- `TaskTransport` 実装（HTTP, gRPC, キュー, SIEM, etc.）
- トランスポートごとの設定（endpoint, credentials, etc.）

**差し替えるべきでない部分**:
- `TaskExecutor` の実行順序（ハンドラ → トランスポートの順序）
- ディスパッチステータスの解決ロジック（AUTO/SEMI_AUTO/MANUAL/MONITOR）
- guardrails の適用（タイムアウト、リトライ、承認要求）

---

## 3. インターフェース設計

### 3.1 TaskTransport

```typescript
/**
 * タスク配信先を抽象化するインターフェース。
 * RemoteTransport（ログ送信用）と同じ設計思想。
 * SDKはzero-depのため、具体的なHTTP/gRPC/キュー実装は利用者が注入する。
 */
export interface TaskTransport {
    /** トランスポート識別名（ログ・メトリクス用） */
    readonly name: string;

    /**
     * タスクを外部システムに配信する。
     * 成功時は TaskTransportResult を返す。
     * 失敗時は throw する（TaskExecutor がエラーを集約する）。
     */
    dispatch(task: GeneratedTask): Promise<TaskTransportResult>;

    /**
     * 接続を閉じる（グレースフルシャットダウン時に呼ばれる）
     */
    close?(): Promise<void>;
}

export interface TaskTransportResult {
    /** トランスポート識別名 */
    transportName: string;
    /** 配信成功したか */
    success: boolean;
    /** 外部システムが返したID（チケットID、メッセージID等） */
    externalId?: string;
    /** エラーメッセージ（success=false の場合） */
    error?: string;
}
```

### 3.2 利用例

```typescript
// HTTP Webhook アダプタ（利用者が実装）
const webhookTransport: TaskTransport = {
    name: "slack-webhook",
    async dispatch(task) {
        const res = await fetch("https://hooks.slack.com/services/xxx", {
            method: "POST",
            body: JSON.stringify({ text: `[${task.severity}] ${task.description}` }),
        });
        return {
            transportName: "slack-webhook",
            success: res.ok,
            error: res.ok ? undefined : `HTTP ${res.status}`,
        };
    },
};

const sentinel = Sentinel.initialize(config, {
    transport: { mode: "local" },
    taskTransports: [webhookTransport],
});
```

---

## 4. TaskExecutor 統合

### 実行フロー

```
dispatch(task)
  → resolveDispatchStatus (AUTO/SEMI_AUTO/MANUAL/MONITOR)
  → if "dispatched":
      1. invokeHandlers (既存コールバック)    ← 変更なし
      2. invokeTransports (新規)             ← 追加
      → エラーはハンドラ・トランスポート合算で集約 (R-2準拠)
```

### 設計判断

- **ハンドラとトランスポートは独立実行**: 片方の失敗がもう片方をブロックしない
- **トランスポートはリトライなし**: リトライは各トランスポート実装の責務（SDK側で二重送信を防ぐ）
- **タイムアウトは共通**: `guardrails.timeoutMs` がハンドラ+トランスポートの合計に適用

---

## 5. YAML 設定

YAML側では `task_transports` セクションで **参照名** を定義する。
実際の `TaskTransport` インスタンスはSDK初期化時にプログラムで注入する。

```yaml
# sentinel.yml
task_transports:
  - name: slack-webhook
    # YAML側のメタデータ（トランスポート実装が参照する）
    endpoint: ${SLACK_WEBHOOK_URL}
    headers:
      Content-Type: application/json
  - name: jira-ticket
    endpoint: ${JIRA_API_URL}
    project_key: OPS
```

**重要**: YAML はメタデータの定義のみ。`TaskTransport` インターフェースの実装は
TypeScript側で注入する必要がある（zero-dep方針のため）。

```typescript
// YAML + プログラム注入の組み合わせ
const config = loadConfigFromYaml("sentinel.yml");
const sentinel = Sentinel.initialize(config, {
    taskTransports: [
        createSlackTransport(config.taskTransports[0]),  // 利用者の実装
        createJiraTransport(config.taskTransports[1]),    // 利用者の実装
    ],
});
```

### YAML Raw型

```typescript
interface RawTaskTransport {
    name: string;
    endpoint?: string;
    headers?: Record<string, string>;
    [key: string]: unknown;  // 拡張フィールド許容
}
```

---

## 6. 影響範囲

| ファイル | 変更内容 |
|----------|----------|
| `src/transport/task-transport.ts` | **新規**: TaskTransport, TaskTransportResult 型定義 |
| `src/core/task/task-executor.ts` | トランスポート受入・実行ロジック追加 |
| `src/configs/sentinel-config.ts` | `taskTransportConfigs` フィールド追加 |
| `src/configs/config-loader.ts` | YAML `task_transports` パース追加 |
| `src/index.ts` | SentinelOptions にtaskTransports追加、エクスポート追加 |
| `tests/unit/core/task-executor-transport.test.ts` | **新規**: トランスポート統合テスト |
| `tests/unit/transport/task-transport.test.ts` | **新規**: インターフェース契約テスト |
| `tests/config/config-loader-transport.test.ts` | **新規**: YAML task_transports パーステスト |

---

## 7. 関連ドキュメント

- `docs/task-gen.md` — タスク生成・承認フロー設計
- `src/transport/transport.ts` — RemoteTransport（ログ用、設計の参考）
- `docs/audit/00-current-analysis.md` — 品質監査レポート
