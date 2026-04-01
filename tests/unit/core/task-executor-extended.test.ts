/**
 * TaskExecutor Extended Tests
 *
 * MEM-01: removeHandler / clearHandlers
 * API-03: guardrails.timeoutMs enforcement
 * OBS-01: onError callback wiring
 */
import { describe, it, expect, vi } from "vitest";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import { createTestTaskRule } from "../../helpers/fixtures";
import type { GeneratedTask } from "../../../src/types/task";

function createTask(overrides: Partial<GeneratedTask> = {}): GeneratedTask {
    const rule = createTestTaskRule();
    return {
        taskId: "task-1",
        ruleId: rule.ruleId,
        eventName: rule.eventName,
        severity: "CRITICAL",
        actionType: rule.actionType,
        executionLevel: "AUTO",
        priority: 1,
        description: rule.description,
        executionParams: {},
        guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
        sourceLog: {
            traceId: "t-1",
            message: "test",
            boundary: "test",
            level: 3,
            timestamp: new Date().toISOString(),
        },
        createdAt: new Date().toISOString(),
        ...overrides,
    };
}

describe("TaskExecutor: removeHandlers (MEM-01)", () => {
    it("removes all handlers for a specific action type", async () => {
        const executor = new TaskExecutor();
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        executor.removeHandlers("SYSTEM_NOTIFICATION");

        const task = createTask({ actionType: "SYSTEM_NOTIFICATION" });
        await executor.dispatch(task);

        expect(handler).not.toHaveBeenCalled();
    });

    it("clearHandlers removes all action types", async () => {
        const executor = new TaskExecutor();
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);
        executor.registerHandler("AI_ANALYZE", handler);

        executor.clearHandlers();

        await executor.dispatch(createTask({ actionType: "SYSTEM_NOTIFICATION" }));
        await executor.dispatch(createTask({ actionType: "AI_ANALYZE" }));

        expect(handler).not.toHaveBeenCalled();
    });

    it("removeHandlers for nonexistent type does not crash", () => {
        const executor = new TaskExecutor();
        expect(() => executor.removeHandlers("NONEXISTENT")).not.toThrow();
    });
});

describe("TaskExecutor: timeoutMs enforcement (API-03)", () => {
    it("times out handler that exceeds timeoutMs", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
            await new Promise((resolve) => setTimeout(resolve, 5000));
        });

        const task = createTask({
            actionType: "SYSTEM_NOTIFICATION",
            guardrails: { requireHumanApproval: false, timeoutMs: 50, maxRetries: 0 },
        });

        const result = await executor.dispatch(task);

        expect(result.status).toBe("failed");
        expect(result.error).toContain("timeout");
    });

    it("does not timeout when handler completes within limit", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
            await new Promise((resolve) => setTimeout(resolve, 10));
        });

        const task = createTask({
            actionType: "SYSTEM_NOTIFICATION",
            guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
        });

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
    });

    it("skips timeout when timeoutMs is 0", async () => {
        const executor = new TaskExecutor();
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const task = createTask({
            actionType: "SYSTEM_NOTIFICATION",
            guardrails: { requireHumanApproval: false, timeoutMs: 0, maxRetries: 0 },
        });

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(handler).toHaveBeenCalled();
    });
});
