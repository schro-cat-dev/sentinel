import { GeneratedTask, TaskResult, TaskDispatchStatus } from "../../types/task";
import { SentinelError } from "../../errors/sentinel-error";

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
 * タスク実行エンジン
 *
 * 生成されたタスクを実行レベルに応じてディスパッチする。
 * SDKではコールバック方式。Goサーバ連携時はgRPC経由でサーバに委譲可能。
 * R-2: 全ハンドラを実行しエラーを集約（1つの失敗で後続を中断しない）。
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

    /** ハンドラ登録のハードリミット (VULN-014) */
    private static readonly HARD_HANDLER_LIMIT = 100;

    /**
     * アクションタイプごとにハンドラを登録。
     * HARD_HANDLER_LIMIT を超えるとエラーをスローする。
     */
    public registerHandler(actionType: string, handler: TaskDispatchHandler): void {
        const existing = this.handlers.get(actionType) ?? [];
        if (existing.length >= TaskExecutor.HARD_HANDLER_LIMIT) {
            throw new Error(
                `Too many handlers for "${actionType}" (${existing.length}). ` +
                `Maximum ${TaskExecutor.HARD_HANDLER_LIMIT} handlers per action type. ` +
                `Call the unsubscribe function returned by onTaskAction() to remove unused handlers.`,
            );
        }
        existing.push(handler);
        this.handlers.set(actionType, existing);
    }

    /**
     * 特定のハンドラを解除する
     */
    public unregisterHandler(actionType: string, handler: TaskDispatchHandler): void {
        const existing = this.handlers.get(actionType);
        if (!existing) return;
        const idx = existing.indexOf(handler);
        if (idx !== -1) existing.splice(idx, 1);
        if (existing.length === 0) this.handlers.delete(actionType);
    }

    /**
     * 指定アクションタイプのハンドラを全て解除 (MEM-01)
     */
    public removeHandlers(actionType: string): void {
        this.handlers.delete(actionType);
    }

    /**
     * 指定アクションタイプのハンドラ数を取得
     */
    public getHandlerCount(actionType: string): number {
        return this.handlers.get(actionType)?.length ?? 0;
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
                    timer = setTimeout(() => reject(new SentinelError("task", "timeout", `Task handler timeout after ${timeoutMs}ms`)), timeoutMs);
                });
                await Promise.race([handlerPromise, timeoutPromise]);
            } finally {
                // setTimeout は同期代入なので timer は必ず defined
                clearTimeout(timer!);
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

        // R-2: Execute all handlers, collect errors, don't stop on first failure
        const errors: Error[] = [];
        for (const handler of handlers) {
            try {
                await handler(task);
            } catch (e) {
                errors.push(e instanceof Error ? e : new Error(String(e)));
            }
        }
        if (errors.length > 0) {
            throw new SentinelError(
                "task",
                "invokeHandlers",
                errors.map((e) => e.message).join("; "),
                errors[0],
            );
        }
    }
}
