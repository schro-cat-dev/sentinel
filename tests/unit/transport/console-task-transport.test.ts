import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ConsoleTaskTransport } from "../../../src/transport/console-task-transport";
import type { GeneratedTask } from "../../../src/types/task";

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
            traceId: "trace-001",
            message: "critical failure",
            boundary: "db",
            level: 6,
            timestamp: "2026-04-02T00:00:00.000Z",
        },
        createdAt: "2026-04-02T00:00:00.000Z",
        ...overrides,
    };
}

describe("ConsoleTaskTransport", () => {
    let infoSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    });

    afterEach(() => {
        infoSpy.mockRestore();
    });

    it("has the configured name", () => {
        const transport = new ConsoleTaskTransport("debug-logger");
        expect(transport.name).toBe("debug-logger");
    });

    it("defaults name to 'console'", () => {
        const transport = new ConsoleTaskTransport();
        expect(transport.name).toBe("console");
    });

    it("dispatch calls console.info with structured JSON", async () => {
        const transport = new ConsoleTaskTransport();
        const task = createTask();

        const result = await transport.dispatch(task);

        expect(infoSpy).toHaveBeenCalledTimes(1);
        const output = infoSpy.mock.calls[0][0] as string;
        const parsed = JSON.parse(output) as Record<string, unknown>;
        expect(parsed.sentinel_task).toBeDefined();
        expect((parsed.sentinel_task as GeneratedTask).taskId).toBe("task-001");
        expect((parsed.sentinel_task as GeneratedTask).severity).toBe("CRITICAL");
        expect((parsed.sentinel_task as GeneratedTask).sourceLog.traceId).toBe("trace-001");
    });

    it("dispatch returns success result", async () => {
        const transport = new ConsoleTaskTransport("test");

        const result = await transport.dispatch(createTask());

        expect(result.transportName).toBe("test");
        expect(result.success).toBe(true);
        expect(result.error).toBeUndefined();
    });

    it("close resolves without error", async () => {
        const transport = new ConsoleTaskTransport();
        await expect(transport.close()).resolves.toBeUndefined();
    });

    it("dispatch after close returns closed error", async () => {
        const transport = new ConsoleTaskTransport();
        await transport.close();

        const result = await transport.dispatch(createTask());

        expect(result.success).toBe(false);
        expect(result.error).toContain("closed");
        expect(infoSpy).not.toHaveBeenCalled();
    });

    it("handles console.info throwing (propagates error)", async () => {
        infoSpy.mockImplementation(() => { throw new Error("console broken"); });
        const transport = new ConsoleTaskTransport();

        await expect(transport.dispatch(createTask())).rejects.toThrow("console broken");
    });

    it("handles multiple rapid dispatches", async () => {
        const transport = new ConsoleTaskTransport();
        const results = await Promise.all(
            Array.from({ length: 50 }, (_, i) =>
                transport.dispatch(createTask({ taskId: `task-${i}` })),
            ),
        );

        expect(results).toHaveLength(50);
        expect(results.every((r) => r.success)).toBe(true);
        expect(infoSpy).toHaveBeenCalledTimes(50);
    });

    it("includes timestamp in output", async () => {
        const transport = new ConsoleTaskTransport();
        await transport.dispatch(createTask());

        const output = infoSpy.mock.calls[0][0] as string;
        const parsed = JSON.parse(output) as Record<string, unknown>;
        expect(typeof parsed.timestamp).toBe("string");
    });
});
