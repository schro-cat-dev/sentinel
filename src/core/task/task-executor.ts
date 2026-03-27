import { GeneratedTask, TaskResult, TaskDispatchStatus } from "../../types/task";

/**
 * タスクディスパッチハンドラの型
 * ユーザーが登録するコールバック
 */
export type TaskDispatchHandler = (task: GeneratedTask) => Promise<void> | void;

/**
 * タスク実行エンジン（v1: コールバックベース）
 *
 * 生成されたタスクを実行レベルに応じてディスパッチする。
 * v1ではコールバック方式。Goサーバ移行後はgRPC経由でサーバに委譲。
 */
export class TaskExecutor {
    private readonly handlers: Map<string, TaskDispatchHandler[]> = new Map();
    private readonly defaultHandler?: TaskDispatchHandler;

    constructor(defaultHandler?: TaskDispatchHandler) {
        this.defaultHandler = defaultHandler;
    }

    /**
     * アクションタイプごとにハンドラを登録
     */
    public registerHandler(actionType: string, handler: TaskDispatchHandler): void {
        const existing = this.handlers.get(actionType) ?? [];
        existing.push(handler);
        this.handlers.set(actionType, existing);
    }

    /**
     * タスクをディスパッチ
     */
    public async dispatch(task: GeneratedTask): Promise<TaskResult> {
        const base: Omit<TaskResult, "status" | "error"> = {
            taskId: task.taskId,
            ruleId: task.ruleId,
            dispatchedAt: new Date().toISOString(),
        };

        // 実行レベルとガードレールに基づくステータス判定
        const status = this.resolveDispatchStatus(task);
        if (status !== "dispatched") {
            return { ...base, status };
        }

        // ハンドラの実行
        try {
            await this.invokeHandlers(task);
            return { ...base, status: "dispatched" };
        } catch (error) {
            return {
                ...base,
                status: "failed",
                error: error instanceof Error ? error.message : String(error),
            };
        }
    }

    private resolveDispatchStatus(task: GeneratedTask): TaskDispatchStatus {
        // ガードレールの承認要求は最優先
        if (task.guardrails.requireHumanApproval) {
            return "blocked_approval";
        }

        switch (task.executionLevel) {
            case "AUTO":
                return "dispatched";
            case "SEMI_AUTO":
                return "dispatched";
            case "MANUAL":
                return "blocked_approval";
            case "MONITOR":
                return "skipped";
            default:
                return "skipped";
        }
    }

    private async invokeHandlers(task: GeneratedTask): Promise<void> {
        const handlers = this.handlers.get(task.actionType) ?? [];

        if (handlers.length === 0 && this.defaultHandler) {
            await this.defaultHandler(task);
            return;
        }

        for (const handler of handlers) {
            await handler(task);
        }
    }
}
