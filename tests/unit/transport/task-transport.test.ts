/**
 * TaskTransport インターフェース契約テスト
 *
 * TaskTransport を実装するモックアダプタが
 * インターフェース契約を満たすことを検証する。
 */
import { describe, it, expect, vi } from "vitest";
import type { TaskTransport, TaskTransportResult } from "../../../src/transport/task-transport";
import type { GeneratedTask } from "../../../src/types/task";

// =========================================================================
// テスト用フィクスチャ
// =========================================================================

function createTestTask(overrides: Partial<GeneratedTask> = {}): GeneratedTask {
    return {
        taskId: "task-001",
        ruleId: "rule-001",
        eventName: "SYSTEM_CRITICAL_FAILURE",
        severity: "CRITICAL",
        actionType: "SYSTEM_NOTIFICATION",
        executionLevel: "AUTO",
        priority: 1,
        description: "Critical system failure detected",
        executionParams: { targetEndpoint: "https://example.com/webhook" },
        guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
        sourceLog: {
            traceId: "trace-001",
            message: "DB connection pool exhausted",
            boundary: "database",
            level: 6,
            timestamp: new Date().toISOString(),
        },
        createdAt: new Date().toISOString(),
        ...overrides,
    };
}

// =========================================================================
// モックトランスポート実装
// =========================================================================

function createMockTransport(overrides: Partial<TaskTransport> = {}): TaskTransport {
    return {
        name: "mock-transport",
        dispatch: vi.fn().mockResolvedValue({
            transportName: "mock-transport",
            success: true,
            externalId: "ext-123",
        } satisfies TaskTransportResult),
        ...overrides,
    };
}

// =========================================================================
// テスト
// =========================================================================

describe("TaskTransport interface contract", () => {
    it("requires name property", () => {
        const transport = createMockTransport();
        expect(transport.name).toBe("mock-transport");
        expect(typeof transport.name).toBe("string");
    });

    it("dispatch returns TaskTransportResult with success=true", async () => {
        const transport = createMockTransport();
        const task = createTestTask();

        const result = await transport.dispatch(task);

        expect(result.transportName).toBe("mock-transport");
        expect(result.success).toBe(true);
        expect(result.externalId).toBe("ext-123");
        expect(result.error).toBeUndefined();
    });

    it("dispatch returns TaskTransportResult with success=false on failure", async () => {
        const transport = createMockTransport({
            dispatch: vi.fn().mockResolvedValue({
                transportName: "mock-transport",
                success: false,
                error: "Connection refused",
            } satisfies TaskTransportResult),
        });
        const task = createTestTask();

        const result = await transport.dispatch(task);

        expect(result.success).toBe(false);
        expect(result.error).toBe("Connection refused");
        expect(result.externalId).toBeUndefined();
    });

    it("dispatch can throw on unrecoverable errors", async () => {
        const transport = createMockTransport({
            dispatch: vi.fn().mockRejectedValue(new Error("Network unreachable")),
        });

        await expect(transport.dispatch(createTestTask())).rejects.toThrow("Network unreachable");
    });

    it("close is optional and returns Promise<void>", async () => {
        // close なし — 問題なし
        const transportNoClose = createMockTransport();
        delete (transportNoClose as Record<string, unknown>).close;
        expect(transportNoClose.close).toBeUndefined();

        // close あり — 呼び出し可能
        const closeFn = vi.fn().mockResolvedValue(undefined);
        const transportWithClose = createMockTransport({ close: closeFn });
        await transportWithClose.close!();
        expect(closeFn).toHaveBeenCalledTimes(1);
    });

    it("dispatch receives the full GeneratedTask object", async () => {
        const dispatchFn = vi.fn().mockResolvedValue({
            transportName: "inspector",
            success: true,
        } satisfies TaskTransportResult);
        const transport = createMockTransport({ name: "inspector", dispatch: dispatchFn });

        const task = createTestTask({
            taskId: "task-specific",
            severity: "HIGH",
            executionParams: { targetEndpoint: "https://jira.example.com/api" },
        });

        await transport.dispatch(task);

        const receivedTask = dispatchFn.mock.calls[0][0] as GeneratedTask;
        expect(receivedTask.taskId).toBe("task-specific");
        expect(receivedTask.severity).toBe("HIGH");
        expect(receivedTask.executionParams.targetEndpoint).toBe("https://jira.example.com/api");
        expect(receivedTask.sourceLog.traceId).toBe("trace-001");
    });

    it("multiple transports can coexist independently", async () => {
        const slackTransport = createMockTransport({
            name: "slack",
            dispatch: vi.fn().mockResolvedValue({
                transportName: "slack",
                success: true,
                externalId: "slack-msg-001",
            } satisfies TaskTransportResult),
        });

        const jiraTransport = createMockTransport({
            name: "jira",
            dispatch: vi.fn().mockResolvedValue({
                transportName: "jira",
                success: true,
                externalId: "JIRA-1234",
            } satisfies TaskTransportResult),
        });

        const task = createTestTask();

        const [slackResult, jiraResult] = await Promise.all([
            slackTransport.dispatch(task),
            jiraTransport.dispatch(task),
        ]);

        expect(slackResult.transportName).toBe("slack");
        expect(slackResult.externalId).toBe("slack-msg-001");
        expect(jiraResult.transportName).toBe("jira");
        expect(jiraResult.externalId).toBe("JIRA-1234");
    });
});
