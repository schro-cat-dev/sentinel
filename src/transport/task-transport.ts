import type { GeneratedTask } from "../types/task";

/**
 * タスク配信先を抽象化するインターフェース。
 *
 * RemoteTransport（ログ送信用）と同じ設計思想。
 * SDKはzero-depのため、具体的なHTTP/gRPC/キュー/SIEM実装は
 * 利用者が TaskTransport を実装して注入する。
 *
 * @example
 * ```typescript
 * // Slack Webhook アダプタ（利用者が実装）
 * const slackTransport: TaskTransport = {
 *     name: "slack-webhook",
 *     async dispatch(task) {
 *         const res = await fetch(endpoint, {
 *             method: "POST",
 *             body: JSON.stringify({ text: `[${task.severity}] ${task.description}` }),
 *         });
 *         return {
 *             transportName: "slack-webhook",
 *             success: res.ok,
 *             error: res.ok ? undefined : `HTTP ${res.status}`,
 *         };
 *     },
 * };
 * ```
 *
 * @see docs/design/task-transport.md — 設計ドキュメント
 * @see src/transport/transport.ts — RemoteTransport（ログ送信用、設計の参考）
 */
export interface TaskTransport {
    /**
     * トランスポート識別名（ログ・メトリクス・エラーメッセージで使用）。
     * 一意であることを推奨するが、SDK側では強制しない。
     */
    readonly name: string;

    /**
     * タスクを外部システムに配信する。
     *
     * - 成功時: `{ success: true, externalId?, ... }` を返す
     * - 部分失敗時: `{ success: false, error }` を返す（他のトランスポートは継続）
     * - 致命的エラー時: throw する（TaskExecutor がエラーを集約する）
     *
     * SDK側ではリトライを行わない。リトライが必要な場合は
     * トランスポート実装内で処理すること（二重配信防止のため）。
     */
    dispatch(task: GeneratedTask): Promise<TaskTransportResult>;

    /**
     * 接続を閉じる（Sentinel.shutdown() 時に呼ばれる）。
     * 省略可。
     */
    close?(): Promise<void>;
}

/**
 * タスク配信結果。
 * 各トランスポートが dispatch() から返す。
 */
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
