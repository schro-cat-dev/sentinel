import { describe, it, expect, beforeEach, vi } from "vitest";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import { GeneratedTask } from "../../../src/types/task";
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
            expect(result.error).toBe("handler failed");
        });

        it("returns failed status when async handler rejects", async () => {
            executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
                throw new Error("async failure");
            });

            const task = createGeneratedTask();
            const result = await executor.dispatch(task);

            expect(result.status).toBe("failed");
            expect(result.error).toBe("async failure");
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
});
