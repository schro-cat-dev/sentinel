import { describe, it, expect, beforeEach, vi } from "vitest";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import { GeneratedTask, TaskExecutionLevel } from "../../../src/types/task";
import { createTestTaskRule } from "../../helpers/fixtures";

const createGeneratedTask = (overrides: Partial<GeneratedTask> = {}): GeneratedTask => ({
    taskId: "task-001",
    ruleId: "rule-001",
    eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "CRITICAL",
    actionType: "SYSTEM_NOTIFICATION",
    executionLevel: "AUTO",
    priority: 1,
    description: "Test task",
    executionParams: { notificationChannel: "#test" },
    guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
    sourceLog: {
        traceId: "trace-001",
        message: "test",
        boundary: "test",
        level: 5,
        timestamp: "2026-01-01T00:00:00Z",
    },
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
});

describe("TaskExecutor", () => {
    let executor: TaskExecutor;

    beforeEach(() => {
        executor = new TaskExecutor();
    });

    describe("dispatch - AUTO execution", () => {
        it("dispatches AUTO tasks immediately", async () => {
            const task = createGeneratedTask({ executionLevel: "AUTO" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
            expect(result.taskId).toBe("task-001");
            expect(result.ruleId).toBe("rule-001");
            expect(result.dispatchedAt).toBeDefined();
        });

        it("calls registered handler for action type", async () => {
            const handler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask();
            await executor.dispatch(task);

            expect(handler).toHaveBeenCalledWith(task);
            expect(handler).toHaveBeenCalledTimes(1);
        });

        it("calls multiple handlers for same action type", async () => {
            const handler1 = vi.fn();
            const handler2 = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler1);
            executor.registerHandler("SYSTEM_NOTIFICATION", handler2);

            const task = createGeneratedTask();
            await executor.dispatch(task);

            expect(handler1).toHaveBeenCalledTimes(1);
            expect(handler2).toHaveBeenCalledTimes(1);
        });
    });

    describe("dispatch - approval required", () => {
        it("blocks when requireHumanApproval is true", async () => {
            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("blocked_approval");
        });

        it("does not call handlers when blocked", async () => {
            const handler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 },
            });
            await executor.dispatch(task);

            expect(handler).not.toHaveBeenCalled();
        });
    });

    describe("dispatch - MANUAL execution", () => {
        it("blocks MANUAL tasks (requires human)", async () => {
            const task = createGeneratedTask({ executionLevel: "MANUAL" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("blocked_approval");
        });
    });

    describe("dispatch - MONITOR execution", () => {
        it("skips MONITOR tasks", async () => {
            const task = createGeneratedTask({ executionLevel: "MONITOR" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("skipped");
        });

        it("does not call handlers for skipped tasks", async () => {
            const handler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({ executionLevel: "MONITOR" });
            await executor.dispatch(task);

            expect(handler).not.toHaveBeenCalled();
        });
    });

    describe("dispatch - SEMI_AUTO execution", () => {
        it("dispatches when approval not required", async () => {
            const task = createGeneratedTask({ executionLevel: "SEMI_AUTO" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
        });

        it("blocks when approval required", async () => {
            const task = createGeneratedTask({
                executionLevel: "SEMI_AUTO",
                guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("blocked_approval");
        });
    });

    describe("error handling", () => {
        it("returns failed status when handler throws", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", () => {
                throw new Error("handler failed");
            });

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);

            expect(result.status).toBe("failed");
            expect(result.error).toContain("handler failed");
        });

        it("returns failed status when async handler rejects", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
                throw new Error("async failure");
            });

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);

            expect(result.status).toBe("failed");
            expect(result.error).toContain("async failure");
        });
    });

    describe("handler failure isolation (R-2)", () => {
        it("executes all handlers even if first one fails (per-handler retry)", async () => {
            const handler1 = vi.fn(() => { throw new Error("handler1 fail"); });
            const handler2 = vi.fn();
            const handler3 = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler1);
            executor.registerHandler("SYSTEM_NOTIFICATION", handler2);
            executor.registerHandler("SYSTEM_NOTIFICATION", handler3);

            const task = createGeneratedTask(); // maxRetries: 3
            const result = await executor.dispatch(task);

            // handler1: always fails → 1 initial + 3 retries = 4 calls
            expect(handler1).toHaveBeenCalledTimes(4);
            // handler2, handler3: succeed on first try, not re-executed
            expect(handler2).toHaveBeenCalledTimes(1);
            expect(handler3).toHaveBeenCalledTimes(1);
            expect(result.status).toBe("failed");
            expect(result.error).toContain("handler1 fail");
        });

        it("executes all handlers even if middle one fails (per-handler retry)", async () => {
            const handler1 = vi.fn();
            const handler2 = vi.fn(async () => { throw new Error("handler2 fail"); });
            const handler3 = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler1);
            executor.registerHandler("SYSTEM_NOTIFICATION", handler2);
            executor.registerHandler("SYSTEM_NOTIFICATION", handler3);

            const task = createGeneratedTask(); // maxRetries: 3
            const result = await executor.dispatch(task);

            expect(handler1).toHaveBeenCalledTimes(1);
            // handler2: always fails → 4 calls
            expect(handler2).toHaveBeenCalledTimes(4);
            expect(handler3).toHaveBeenCalledTimes(1);
            expect(result.status).toBe("failed");
        });

        it("aggregates multiple handler errors", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", () => { throw new Error("err1"); });
            executor.registerHandler("SYSTEM_NOTIFICATION", () => { throw new Error("err2"); });
            executor.registerHandler("SYSTEM_NOTIFICATION", vi.fn());

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);

            expect(result.status).toBe("failed");
            expect(result.error).toContain("err1");
            expect(result.error).toContain("err2");
        });

        it("returns dispatched when all handlers succeed", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", vi.fn());
            executor.registerHandler("SYSTEM_NOTIFICATION", vi.fn());

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
        });
    });

    describe("default handler", () => {
        it("calls default handler when no specific handler registered", async () => {
            const defaultHandler = vi.fn();
            const executorWithDefault = new TaskExecutor(defaultHandler);

            const task = createGeneratedTask({ actionType: "EXTERNAL_WEBHOOK" });
            await executorWithDefault.dispatch(task);

            expect(defaultHandler).toHaveBeenCalledWith(task);
        });

        it("does not call default handler when specific handler exists", async () => {
            const defaultHandler = vi.fn();
            const specificHandler = vi.fn();
            const executorWithDefault = new TaskExecutor(defaultHandler);
            executorWithDefault.registerHandler("SYSTEM_NOTIFICATION", specificHandler);

            const task = createGeneratedTask();
            await executorWithDefault.dispatch(task);

            expect(specificHandler).toHaveBeenCalled();
            expect(defaultHandler).not.toHaveBeenCalled();
        });
    });

    describe("dispatch - unknown executionLevel", () => {
        it("returns skipped for unknown executionLevel", async () => {
            const task = createGeneratedTask({
                executionLevel: "UNKNOWN" as unknown as TaskExecutionLevel,
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("skipped");
        });
    });

    describe("different action types", () => {
        it("routes to correct handler based on actionType", async () => {
            const notifyHandler = vi.fn();
            const analyzeHandler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", notifyHandler);
            executor.registerHandler("AI_ANALYZE", analyzeHandler);

            const notifyTask = createGeneratedTask({ actionType: "SYSTEM_NOTIFICATION" });
            const analyzeTask = createGeneratedTask({ actionType: "AI_ANALYZE", taskId: "task-002" });

            await executor.dispatch(notifyTask);
            await executor.dispatch(analyzeTask);

            expect(notifyHandler).toHaveBeenCalledTimes(1);
            expect(analyzeHandler).toHaveBeenCalledTimes(1);
        });
    });

    describe("unregisterHandler edge cases", () => {
        it("unregistering a handler not in the list does nothing", () => {
            const handlerA = vi.fn();
            const handlerB = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handlerA);

            // handlerB was never registered - indexOf returns -1
            executor.unregisterHandler("SYSTEM_NOTIFICATION", handlerB);

            // handlerA still there
            expect(executor.getHandlerCount("SYSTEM_NOTIFICATION")).toBe(1);
        });

        it("unregistering from nonexistent action type does nothing", () => {
            const handler = vi.fn();
            // No handlers registered for this type - early return
            executor.unregisterHandler("NONEXISTENT", handler);
            expect(executor.getHandlerCount("NONEXISTENT")).toBe(0);
        });

        it("unregistering the last handler deletes the action type entry", () => {
            const handler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);
            executor.unregisterHandler("SYSTEM_NOTIFICATION", handler);
            expect(executor.getHandlerCount("SYSTEM_NOTIFICATION")).toBe(0);
        });
    });

    describe("getHandlerCount edge cases", () => {
        it("returns 0 for action type with no registered handlers", () => {
            expect(executor.getHandlerCount("NONEXISTENT")).toBe(0);
        });
    });

    describe("error handling edge cases", () => {
        it("returns stringified error when handler throws non-Error", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", () => {
                throw "string-error" as unknown;
            });

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);

            expect(result.status).toBe("failed");
            expect(result.error).toBe("string-error");
        });
    });

    describe("SEMI_AUTO with confirm handler", () => {
        it("dispatches when confirm handler returns true", async () => {
            executor.setConfirmHandler(() => true);
            const task = createGeneratedTask({ executionLevel: "SEMI_AUTO" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
        });

        it("blocks when confirm handler returns false", async () => {
            executor.setConfirmHandler(() => false);
            const task = createGeneratedTask({ executionLevel: "SEMI_AUTO" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("blocked_approval");
        });

        it("handles async confirm handler returning true", async () => {
            executor.setConfirmHandler(async () => true);
            const task = createGeneratedTask({ executionLevel: "SEMI_AUTO" });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
        });
    });

    describe("timeout with negative timeoutMs", () => {
        it("skips timeout when timeoutMs is negative (treated as <= 0)", async () => {
            const handler = vi.fn();
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: false, timeoutMs: -1, maxRetries: 0 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
            expect(handler).toHaveBeenCalled();
        });
    });

    describe("maxRetries (per-handler)", () => {
        it("retries individual handler on failure and succeeds on subsequent attempt", async () => {
            let callCount = 0;
            const handler = vi.fn(async () => {
                callCount++;
                if (callCount < 2) throw new Error("transient");
            });
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 2 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
            expect(handler).toHaveBeenCalledTimes(2);
        });

        it("fails after exhausting all retries for a handler", async () => {
            const handler = vi.fn(async () => { throw new Error("always fail"); });
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 2 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("failed");
            // 1 initial + 2 retries = 3 total calls
            expect(handler).toHaveBeenCalledTimes(3);
        });

        it("does not retry when maxRetries is 0", async () => {
            const handler = vi.fn(async () => { throw new Error("fail"); });
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("failed");
            expect(handler).toHaveBeenCalledTimes(1);
        });

        it("only retries the failing handler, not successful ones", async () => {
            const successHandler = vi.fn();
            let failCount = 0;
            const transientHandler = vi.fn(async () => {
                failCount++;
                if (failCount <= 2) throw new Error("transient");
            });
            executor.registerHandler("SYSTEM_NOTIFICATION", successHandler);
            executor.registerHandler("SYSTEM_NOTIFICATION", transientHandler);

            const task = createGeneratedTask({
                guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 3 },
            });
            const result = await executor.dispatch(task);
            expect(result.status).toBe("dispatched");
            // successHandler succeeds on first try — no re-execution
            expect(successHandler).toHaveBeenCalledTimes(1);
            // transientHandler fails twice then succeeds — 3 calls
            expect(transientHandler).toHaveBeenCalledTimes(3);
        });
    });
});
