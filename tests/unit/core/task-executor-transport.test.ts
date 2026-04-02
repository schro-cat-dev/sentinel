/**
 * TaskExecutor + TaskTransport 統合テスト
 *
 * ハンドラ（既存コールバック方式）とトランスポート（新アダプタ方式）の
 * 共存・独立実行・エラー集約を検証する。
 */
import { describe, it, expect, vi } from "vitest";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import type { TaskTransport, TaskTransportResult } from "../../../src/transport/task-transport";
import type { GeneratedTask } from "../../../src/types/task";

// =========================================================================
// フィクスチャ
// =========================================================================

function createTask(overrides: Partial<GeneratedTask> = {}): GeneratedTask {
    return {
        taskId: "task-001",
        ruleId: "rule-001",
        eventName: "SYSTEM_CRITICAL_FAILURE",
        severity: "CRITICAL",
        actionType: "SYSTEM_NOTIFICATION",
        executionLevel: "AUTO",
        priority: 1,
        description: "Test task",
        executionParams: {},
        guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 0 },
        sourceLog: {
            traceId: "t-1",
            message: "test",
            boundary: "test",
            level: 6,
            timestamp: new Date().toISOString(),
        },
        createdAt: new Date().toISOString(),
        ...overrides,
    };
}

function createMockTransport(name: string, overrides: Partial<TaskTransport> = {}): TaskTransport {
    return {
        name,
        dispatch: vi.fn().mockResolvedValue({
            transportName: name,
            success: true,
        } satisfies TaskTransportResult),
        ...overrides,
    };
}

// =========================================================================
// テスト: トランスポート基本動作
// =========================================================================

describe("TaskExecutor: transport dispatch", () => {
    it("dispatches task to registered transports", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);

        const task = createTask();
        const result = await executor.dispatch(task);

        expect(result.status).toBe("dispatched");
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
        expect(transport.dispatch).toHaveBeenCalledWith(task);
    });

    it("dispatches to multiple transports", async () => {
        const slack = createMockTransport("slack");
        const jira = createMockTransport("jira");
        const executor = new TaskExecutor(undefined, [slack, jira]);

        const task = createTask();
        await executor.dispatch(task);

        expect(slack.dispatch).toHaveBeenCalledTimes(1);
        expect(jira.dispatch).toHaveBeenCalledTimes(1);
    });

    it("executes both handlers and transports", async () => {
        const transport = createMockTransport("webhook");
        const handler = vi.fn();
        const executor = new TaskExecutor(undefined, [transport]);
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const task = createTask();
        await executor.dispatch(task);

        expect(handler).toHaveBeenCalledTimes(1);
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });

    it("does not dispatch to transports when status is not dispatched", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);

        // MANUAL → blocked_approval
        const task = createTask({ executionLevel: "MANUAL" });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("blocked_approval");
        expect(transport.dispatch).not.toHaveBeenCalled();
    });

    it("does not dispatch to transports when MONITOR", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);

        const task = createTask({ executionLevel: "MONITOR" });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("skipped");
        expect(transport.dispatch).not.toHaveBeenCalled();
    });
});

// =========================================================================
// テスト: エラー集約
// =========================================================================

describe("TaskExecutor: transport error handling", () => {
    it("continues dispatching when one transport throws", async () => {
        const failing = createMockTransport("failing", {
            dispatch: vi.fn().mockRejectedValue(new Error("Connection refused")),
        });
        const succeeding = createMockTransport("succeeding");
        const executor = new TaskExecutor(undefined, [failing, succeeding]);

        const task = createTask();
        const result = await executor.dispatch(task);

        // 全トランスポート実行、エラーは集約
        expect(succeeding.dispatch).toHaveBeenCalledTimes(1);
        expect(result.status).toBe("failed");
        expect(result.error).toContain("Connection refused");
    });

    it("aggregates errors from handlers and transports", async () => {
        const failingTransport = createMockTransport("failing-transport", {
            dispatch: vi.fn().mockRejectedValue(new Error("Transport error")),
        });
        const failingHandler = vi.fn().mockRejectedValue(new Error("Handler error"));
        const executor = new TaskExecutor(undefined, [failingTransport]);
        executor.registerHandler("SYSTEM_NOTIFICATION", failingHandler);

        const task = createTask();
        const result = await executor.dispatch(task);

        expect(result.status).toBe("failed");
        expect(result.error).toContain("Handler error");
        expect(result.error).toContain("Transport error");
    });

    it("handler failure does not prevent transport dispatch", async () => {
        const transport = createMockTransport("slack");
        const failingHandler = vi.fn().mockRejectedValue(new Error("Handler error"));
        const executor = new TaskExecutor(undefined, [transport]);
        executor.registerHandler("SYSTEM_NOTIFICATION", failingHandler);

        const task = createTask();
        await executor.dispatch(task);

        // ハンドラ失敗してもトランスポートは実行される
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });

    it("transport failure does not prevent other transport dispatch", async () => {
        const failing = createMockTransport("failing", {
            dispatch: vi.fn().mockRejectedValue(new Error("fail")),
        });
        const ok = createMockTransport("ok");
        const executor = new TaskExecutor(undefined, [failing, ok]);

        await executor.dispatch(createTask());

        expect(ok.dispatch).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: タイムアウト
// =========================================================================

describe("TaskExecutor: transport timeout", () => {
    it("transport is subject to task-level timeout", async () => {
        const slowTransport = createMockTransport("slow", {
            dispatch: vi.fn().mockImplementation(
                () => new Promise((resolve) => setTimeout(() => resolve({
                    transportName: "slow",
                    success: true,
                }), 5000)),
            ),
        });
        const executor = new TaskExecutor(undefined, [slowTransport]);

        const task = createTask({
            guardrails: { requireHumanApproval: false, timeoutMs: 50, maxRetries: 0 },
        });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("failed");
        expect(result.error).toContain("timeout");
    });
});

// =========================================================================
// テスト: トランスポートなし（後方互換）
// =========================================================================

describe("TaskExecutor: backward compatibility (no transports)", () => {
    it("works without transports (existing behavior unchanged)", async () => {
        const handler = vi.fn();
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("dispatched");
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it("works with empty transport array", async () => {
        const handler = vi.fn();
        const executor = new TaskExecutor(undefined, []);
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("dispatched");
        expect(handler).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: close
// =========================================================================

describe("TaskExecutor: transport close", () => {
    it("closeTransports calls close on all transports", async () => {
        const t1 = createMockTransport("t1", { close: vi.fn().mockResolvedValue(undefined) });
        const t2 = createMockTransport("t2", { close: vi.fn().mockResolvedValue(undefined) });
        const t3 = createMockTransport("t3"); // close なし
        const executor = new TaskExecutor(undefined, [t1, t2, t3]);

        await executor.closeTransports();

        expect(t1.close).toHaveBeenCalledTimes(1);
        expect(t2.close).toHaveBeenCalledTimes(1);
    });

    it("closeTransports tolerates close errors", async () => {
        const failing = createMockTransport("failing", {
            close: vi.fn().mockRejectedValue(new Error("close error")),
        });
        const ok = createMockTransport("ok", { close: vi.fn().mockResolvedValue(undefined) });
        const executor = new TaskExecutor(undefined, [failing, ok]);

        // エラーでクラッシュしない
        await expect(executor.closeTransports()).resolves.toBeUndefined();
        expect(ok.close).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: SEMI_AUTO + トランスポート
// =========================================================================

describe("TaskExecutor: SEMI_AUTO + transports", () => {
    it("dispatches to transports when confirmHandler approves", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);
        executor.setConfirmHandler(() => true);

        const task = createTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("dispatched");
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });

    it("does not dispatch to transports when confirmHandler rejects", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);
        executor.setConfirmHandler(() => false);

        const task = createTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("blocked_approval");
        expect(transport.dispatch).not.toHaveBeenCalled();
    });

    it("dispatches to transports when SEMI_AUTO and no confirmHandler (AUTO fallback)", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);
        // confirmHandler 未設定 → AUTO と同じ動作

        const task = createTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("dispatched");
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: requireHumanApproval + トランスポート
// =========================================================================

describe("TaskExecutor: requireHumanApproval + transports", () => {
    it("blocks transports when requireHumanApproval is true (AUTO)", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);

        const task = createTask({
            executionLevel: "AUTO",
            guardrails: { requireHumanApproval: true, timeoutMs: 30000, maxRetries: 0 },
        });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("blocked_approval");
        expect(transport.dispatch).not.toHaveBeenCalled();
    });

    it("blocks transports when requireHumanApproval is true (SEMI_AUTO)", async () => {
        const transport = createMockTransport("slack");
        const executor = new TaskExecutor(undefined, [transport]);
        executor.setConfirmHandler(() => true);

        const task = createTask({
            executionLevel: "SEMI_AUTO",
            guardrails: { requireHumanApproval: true, timeoutMs: 30000, maxRetries: 0 },
        });
        const result = await executor.dispatch(task);

        expect(result.status).toBe("blocked_approval");
        expect(transport.dispatch).not.toHaveBeenCalled();
    });
});

// =========================================================================
// テスト: defaultHandler + トランスポート
// =========================================================================

describe("TaskExecutor: defaultHandler + transports", () => {
    it("executes defaultHandler AND transports when no actionType handler", async () => {
        const defaultHandler = vi.fn();
        const transport = createMockTransport("webhook");
        const executor = new TaskExecutor(defaultHandler, [transport]);

        const task = createTask();
        const result = await executor.dispatch(task);

        expect(result.status).toBe("dispatched");
        expect(defaultHandler).toHaveBeenCalledTimes(1);
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });

    it("executes actionType handler (not default) AND transports", async () => {
        const defaultHandler = vi.fn();
        const specificHandler = vi.fn();
        const transport = createMockTransport("webhook");
        const executor = new TaskExecutor(defaultHandler, [transport]);
        executor.registerHandler("SYSTEM_NOTIFICATION", specificHandler);

        const task = createTask();
        await executor.dispatch(task);

        expect(defaultHandler).not.toHaveBeenCalled();
        expect(specificHandler).toHaveBeenCalledTimes(1);
        expect(transport.dispatch).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: success=false ハンドリング
// =========================================================================

describe("TaskExecutor: transport success=false handling", () => {
    it("treats success=false as error", async () => {
        const transport = createMockTransport("failing", {
            dispatch: vi.fn().mockResolvedValue({
                transportName: "failing",
                success: false,
                error: "Rate limited",
            } satisfies TaskTransportResult),
        });
        const executor = new TaskExecutor(undefined, [transport]);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("failed");
        expect(result.error).toContain("Rate limited");
        expect(result.error).toContain("failing");
    });

    it("treats success=false without error message as error", async () => {
        const transport = createMockTransport("failing", {
            dispatch: vi.fn().mockResolvedValue({
                transportName: "failing",
                success: false,
            } satisfies TaskTransportResult),
        });
        const executor = new TaskExecutor(undefined, [transport]);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("failed");
        expect(result.error).toContain("success=false");
    });

    it("success=true transport does not cause error", async () => {
        const transport = createMockTransport("ok", {
            dispatch: vi.fn().mockResolvedValue({
                transportName: "ok",
                success: true,
                externalId: "ext-123",
            } satisfies TaskTransportResult),
        });
        const executor = new TaskExecutor(undefined, [transport]);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("dispatched");
        expect(result.error).toBeUndefined();
    });

    it("mixed success/failure across transports aggregates errors", async () => {
        const ok = createMockTransport("ok");
        const failing = createMockTransport("failing", {
            dispatch: vi.fn().mockResolvedValue({
                transportName: "failing",
                success: false,
                error: "503 Service Unavailable",
            } satisfies TaskTransportResult),
        });
        const executor = new TaskExecutor(undefined, [ok, failing]);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("failed");
        expect(result.error).toContain("503 Service Unavailable");
        // ok transport は呼ばれている
        expect(ok.dispatch).toHaveBeenCalledTimes(1);
    });
});

// =========================================================================
// テスト: エッジケース
// =========================================================================

describe("TaskExecutor: transport edge cases", () => {
    it("no handlers and no transports — dispatched but nothing happens", async () => {
        const executor = new TaskExecutor(undefined, []);

        const result = await executor.dispatch(createTask());

        expect(result.status).toBe("dispatched");
        expect(result.error).toBeUndefined();
    });

    it("transport receives exact same task object (deep equality)", async () => {
        const dispatchFn = vi.fn().mockResolvedValue({
            transportName: "inspector",
            success: true,
        } satisfies TaskTransportResult);
        const transport = createMockTransport("inspector", { dispatch: dispatchFn });
        const executor = new TaskExecutor(undefined, [transport]);

        const task = createTask({
            taskId: "deep-eq-001",
            severity: "HIGH",
            executionParams: { targetEndpoint: "https://api.example.com" },
            sourceLog: {
                traceId: "trace-deep",
                message: "deep equality test",
                boundary: "test",
                level: 5,
                timestamp: "2026-04-02T00:00:00.000Z",
            },
        });

        await executor.dispatch(task);

        const received = dispatchFn.mock.calls[0][0] as GeneratedTask;
        expect(received).toBe(task); // 同一参照
        expect(received.taskId).toBe("deep-eq-001");
        expect(received.severity).toBe("HIGH");
        expect(received.executionParams.targetEndpoint).toBe("https://api.example.com");
        expect(received.sourceLog.traceId).toBe("trace-deep");
    });
});
