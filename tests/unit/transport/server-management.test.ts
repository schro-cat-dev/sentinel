/**
 * Phase 3: ServerManagementTransport integration tests
 *
 * Verifies Sentinel public API for task approval, task status,
 * and block management via ServerManagementTransport.
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import type { ServerManagementTransport } from "../../../src/transport/server-management-transport";

const baseConfig = createDefaultConfig({
    projectName: "mgmt-test",
    serviceId: "test-svc",
    security: { enableHashChain: false },
    masking: { enabled: false, rules: [], preserveFields: [] },
    taskRules: [],
});

function createMockManagement(): ServerManagementTransport {
    return {
        approveTask: vi.fn(async (taskId, approverId, reason) => ({
            taskId,
            status: "dispatched",
            dispatchedAt: "2026-04-02T00:00:00Z",
        })),
        rejectTask: vi.fn(async (taskId, rejectorId, reason) => ({
            taskId,
            status: "rejected",
        })),
        getTaskStatus: vi.fn(async (taskId) => ({
            taskId,
            ruleId: "rule-1",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            status: "dispatched",
            actionType: "SYSTEM_NOTIFICATION",
            severity: "HIGH",
            executionLevel: "AUTO",
            description: "test task",
            sourceTraceId: "trace-1",
            createdAt: "2026-04-02T00:00:00Z",
            updatedAt: "2026-04-02T00:00:01Z",
        })),
        listTasks: vi.fn(async (filter) => ({
            tasks: [{
                taskId: "task-1",
                ruleId: "rule-1",
                eventName: "SYSTEM_CRITICAL_FAILURE",
                status: "dispatched",
                actionType: "SYSTEM_NOTIFICATION",
                severity: "HIGH",
                executionLevel: "AUTO",
                description: "test",
                sourceTraceId: "trace-1",
                createdAt: "2026-04-02T00:00:00Z",
                updatedAt: "2026-04-02T00:00:01Z",
            }],
            totalCount: 1,
        })),
        listPendingBlocks: vi.fn(async () => [{
            blockId: "block-1",
            actionType: "block_ip",
            targetIp: "10.0.0.1",
            targetUserId: "",
            reason: "brute force",
            status: "pending",
            createdAt: "2026-04-02T00:00:00Z",
        }]),
        approveBlock: vi.fn(async (blockId, approverId) => ({
            blockId,
            success: true,
            target: "10.0.0.1",
        })),
        rejectBlock: vi.fn(async (blockId, rejectorId) => ({
            blockId,
            status: "rejected",
        })),
    };
}

afterEach(() => Sentinel.reset());

describe("Phase 3-B: Task Approval API", () => {
    it("approveTask calls management transport", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.approveTask("task-1", "admin", "looks good");
        expect(result.status).toBe("dispatched");
        expect(mgmt.approveTask).toHaveBeenCalledWith("task-1", "admin", "looks good");
    });

    it("rejectTask calls management transport", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.rejectTask("task-1", "admin", "false positive");
        expect(result.status).toBe("rejected");
        expect(mgmt.rejectTask).toHaveBeenCalledWith("task-1", "admin", "false positive");
    });

    it("throws when task approval is disabled", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        await expect(sentinel.approveTask("task-1", "admin", "ok")).rejects.toThrow("Task approval is not enabled");
    });

    it("throws when no management transport is provided", async () => {
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
        );
        await expect(sentinel.approveTask("task-1", "admin", "ok")).rejects.toThrow("ServerManagementTransport is not configured");
    });

    it("throws after shutdown", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );
        await sentinel.shutdown();
        await expect(sentinel.approveTask("task-1", "admin", "ok")).rejects.toThrow("shutdown");
    });
});

describe("Phase 3-D: Task Status API", () => {
    it("getTaskStatus returns task details", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskStatusEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.getTaskStatus("task-1");
        expect(result.taskId).toBe("task-1");
        expect(result.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(mgmt.getTaskStatus).toHaveBeenCalledWith("task-1");
    });

    it("listTasks returns filtered results", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskStatusEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.listTasks({ eventName: "SYSTEM_CRITICAL_FAILURE", limit: 10 });
        expect(result.tasks.length).toBe(1);
        expect(result.totalCount).toBe(1);
    });

    it("throws when task status is disabled", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        await expect(sentinel.getTaskStatus("task-1")).rejects.toThrow("Task status query is not enabled");
    });
});

describe("Phase 3-B: Block Management API", () => {
    it("listPendingBlocks returns blocks", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );

        const blocks = await sentinel.listPendingBlocks();
        expect(blocks.length).toBe(1);
        expect(blocks[0].targetIp).toBe("10.0.0.1");
    });

    it("approveBlock calls management transport", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.approveBlock("block-1", "admin");
        expect(result.success).toBe(true);
        expect(mgmt.approveBlock).toHaveBeenCalledWith("block-1", "admin");
    });

    it("rejectBlock calls management transport", async () => {
        const mgmt = createMockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );

        const result = await sentinel.rejectBlock("block-1", "admin");
        expect(result.status).toBe("rejected");
    });
});
