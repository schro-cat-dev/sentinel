import { GeneratedTask, TaskResult, TaskDispatchStatus } from "../../types/task";
import { SentinelError } from "../../errors/sentinel-error";
import type { TaskTransport } from "../../transport/task-transport";

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
    private readonly transports: readonly TaskTransport[];
    private confirmHandler?: TaskConfirmHandler;

    constructor(defaultHandler?: TaskDispatchHandler, transports?: readonly TaskTransport[]) {
        this.defaultHandler = defaultHandler;
        this.transports = transports ?? [];
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
     * 全トランスポートの接続を閉じる（Sentinel.shutdown() から呼ばれる）。
     * 個別のclose失敗は握りつぶす（best-effort）。
     */
    public async closeTransports(): Promise<void> {
        for (const transport of this.transports) {
            try {
                await transport.close?.();
            } catch {
                // best-effort: close errors are silently swallowed
            }
        }
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

        // API-03: guardrails.timeoutMs を適用、maxRetries はハンドラ単位で適用
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

    /**
     * ハンドラ + トランスポートを実行し、エラーを集約する。
     * timeoutMs > 0: Promise.race でタイムアウト適用
     * timeoutMs <= 0: タイムアウト無効（無制限待機）
     */
    private async invokeWithTimeout(task: GeneratedTask): Promise<void> {
        const timeoutMs = task.guardrails.timeoutMs;
        if (timeoutMs > 0) {
            let timer: ReturnType<typeof setTimeout> | undefined;
            try {
                const allPromise = this.invokeAll(task);
                const timeoutPromise = new Promise<never>((_, reject) => {
                    timer = setTimeout(() => reject(new SentinelError("task", "timeout", `Task handler timeout after ${timeoutMs}ms`)), timeoutMs);
                });
                await Promise.race([allPromise, timeoutPromise]);
            } finally {
                // setTimeout は同期代入なので timer は必ず defined
                clearTimeout(timer!);
            }
        } else {
            await this.invokeAll(task);
        }
    }

    /**
     * ハンドラ → トランスポートを順に実行し、エラーを集約して throw。
     * ハンドラの失敗がトランスポートをブロックしない（R-2準拠）。
     */
    private async invokeAll(task: GeneratedTask): Promise<void> {
        const handlerErrors = await this.invokeHandlers(task);
        const transportErrors = await this.invokeTransports(task);
        const allErrors = [...handlerErrors, ...transportErrors];

        if (allErrors.length > 0) {
            throw new SentinelError(
                "task",
                "invokeAll",
                allErrors.map((e) => e.message).join("; "),
                allErrors[0],
            );
        }
    }

    private async invokeHandlers(task: GeneratedTask): Promise<Error[]> {
        const handlers = this.handlers.get(task.actionType) ?? [];
        const errors: Error[] = [];

        if (handlers.length === 0 && this.defaultHandler) {
            try {
                await this.invokeWithRetry(this.defaultHandler, task);
            } catch (e) {
                errors.push(e instanceof Error ? e : new Error(String(e)));
            }
            return errors;
        }

        // R-2: Execute all handlers, collect errors, don't stop on first failure
        // maxRetries はハンドラ単位で適用 — 成功したハンドラを再実行しない
        for (const handler of handlers) {
            try {
                await this.invokeWithRetry(handler, task);
            } catch (e) {
                errors.push(e instanceof Error ? e : new Error(String(e)));
            }
        }
        return errors;
    }

    /**
     * 登録済みトランスポートにタスクを配信する。
     * R-2準拠: 全トランスポートを実行し、エラーを集約する。
     * SDK側ではリトライしない（トランスポート実装の責務）。
     */
    private async invokeTransports(task: GeneratedTask): Promise<Error[]> {
        const errors: Error[] = [];
        for (const transport of this.transports) {
            try {
                await transport.dispatch(task);
            } catch (e) {
                errors.push(
                    e instanceof Error
                        ? new Error(`[${transport.name}] ${e.message}`)
                        : new Error(`[${transport.name}] ${String(e)}`),
                );
            }
        }
        return errors;
    }

    /** ハンドラリトライの上限 */
    private static readonly MAX_HANDLER_RETRIES = 10;

    /**
     * 個別ハンドラをmaxRetries回までリトライする。
     * 成功したハンドラは再実行されない（二重通知・二重ブロック防止）。
     *
     * maxRetries は taskRules[].guardrails.max_retries で利用者が設定可能（0〜10）。
     * 負の値は0に、上限超過はMAX_HANDLER_RETRIES(10)にクランプされる。
     */
    private async invokeWithRetry(handler: TaskDispatchHandler, task: GeneratedTask): Promise<void> {
        const maxRetries = Math.min(TaskExecutor.MAX_HANDLER_RETRIES, Math.max(0, task.guardrails.maxRetries));
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                await handler(task);
                return;
            } catch (e) {
                if (attempt === maxRetries) throw e;
            }
        }
    }
}
