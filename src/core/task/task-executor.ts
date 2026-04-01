import { GeneratedTask, TaskResult, TaskDispatchStatus } from "../../types/task";

/**
 * タスクディスパッチハンドラの型
 * ユーザーが登録するコールバック
 */
export type TaskDispatchHandler = (task: GeneratedTask) => Promise<void> | void;

/**
 * SEMI_AUTO用の確認ハンドラ。
 * true: ディスパッチ続行  false: blocked_approval として中断
 */
export type TaskConfirmHandler = (task: GeneratedTask) => Promise<boolean> | boolean;

/**
 * タスク実行エンジン（v1: コールバックベース）
 *
 * 生成されたタスクを実行レベルに応じてディスパッチする。
 * v1ではコールバック方式。Goサーバ移行後はgRPC経由でサーバに委譲。
 */
export class TaskExecutor {
    private readonly handlers: Map<string, TaskDispatchHandler[]> = new Map();
    private readonly defaultHandler?: TaskDispatchHandler;
    private confirmHandler?: TaskConfirmHandler;

    constructor(defaultHandler?: TaskDispatchHandler) {
        this.defaultHandler = defaultHandler;
    }

    /**
     * SEMI_AUTO用の確認ハンドラを登録
     * 未登録時はSEMI_AUTOがAUTOと同じ動作になる（後方互換）
     */
    public setConfirmHandler(handler: TaskConfirmHandler): void {
        this.confirmHandler = handler;
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
     * 指定アクションタイプのハンドラを全て解除 (MEM-01)
     */
    public removeHandlers(actionType: string): void {
        this.handlers.delete(actionType);
    }

    /**
     * 全ハンドラを解除
     */
    public clearHandlers(): void {
        this.handlers.clear();
        this.confirmHandler = undefined;
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

        const status = await this.resolveDispatchStatus(task);
        if (status !== "dispatched") {
            return { ...base, status };
        }

        // API-03: guardrails.timeoutMs を適用
        try {
            await this.invokeWithTimeout(task);
            return { ...base, status: "dispatched" };
        } catch (error) {
            return {
                ...base,
                status: "failed",
                error: error instanceof Error ? error.message : String(error),
            };
        }
    }

    private async resolveDispatchStatus(task: GeneratedTask): Promise<TaskDispatchStatus> {
        if (task.guardrails.requireHumanApproval) {
            return "blocked_approval";
        }

        switch (task.executionLevel) {
            case "AUTO":
                return "dispatched";
            case "SEMI_AUTO":
                // 確認ハンドラが登録されていれば確認を経由。未登録ならAUTOと同じ。
                if (this.confirmHandler) {
                    const confirmed = await this.confirmHandler(task);
                    return confirmed ? "dispatched" : "blocked_approval";
                }
                return "dispatched";
            case "MANUAL":
                return "blocked_approval";
            case "MONITOR":
                return "skipped";
            default:
                return "skipped";
        }
    }

    private async invokeWithTimeout(task: GeneratedTask): Promise<void> {
        const timeoutMs = task.guardrails.timeoutMs;
        if (timeoutMs > 0) {
            let timer: ReturnType<typeof setTimeout> | undefined;
            try {
                const handlerPromise = this.invokeHandlers(task);
                const timeoutPromise = new Promise<never>((_, reject) => {
                    timer = setTimeout(() => reject(new Error(`Task handler timeout after ${timeoutMs}ms`)), timeoutMs);
                });
                await Promise.race([handlerPromise, timeoutPromise]);
            } finally {
                if (timer !== undefined) clearTimeout(timer);
            }
        } else {
            await this.invokeHandlers(task);
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
