import type { GeneratedTask } from "../types/task";
import type { TaskTransport, TaskTransportResult } from "./task-transport";

/**
 * デバッグ/開発用の組み込みタスクトランスポート。
 * タスクを console.info に構造化JSON形式で出力する。
 *
 * @example
 * ```typescript
 * const sentinel = Sentinel.initialize(config, {
 *     taskTransports: [new ConsoleTaskTransport("debug")],
 * });
 * ```
 *
 * YAML 設定の `type: "console"` で自動生成される。
 */
export class ConsoleTaskTransport implements TaskTransport {
    public readonly name: string;
    private closed = false;

    constructor(name?: string) {
        this.name = name ?? "console";
    }

    async dispatch(task: GeneratedTask): Promise<TaskTransportResult> {
        if (this.closed) {
            return {
                transportName: this.name,
                success: false,
                error: `[${this.name}] transport is closed`,
            };
        }

        const output = JSON.stringify({
            sentinel_task: task,
            timestamp: new Date().toISOString(),
        });
        console.info(output);

        return {
            transportName: this.name,
            success: true,
        };
    }

    async close(): Promise<void> {
        this.closed = true;
    }
}
