/**
 * Integration Config Matrix Tests
 *
 * sentinel.yaml の integration セクションの設定パターン組み合わせを検証。
 * 各機能が設定値に応じて正しく有効/無効になることを確認する。
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../src/index";
import type { RemoteTransport } from "../../src/transport/transport";
import type { ServerManagementTransport } from "../../src/transport/server-management-transport";
import type { IngestionResult } from "../../src/core/engine/types";
import type { Log } from "../../src/types/log";

afterEach(() => Sentinel.reset());

const baseConfig = createDefaultConfig({
    projectName: "matrix-test",
    serviceId: "matrix-svc",
    security: { enableHashChain: false },
    masking: { enabled: false, rules: [], preserveFields: [] },
    taskRules: [],
});

function mockTransport(): RemoteTransport {
    return {
        async send(log: Log): Promise<IngestionResult> {
            return {
                traceId: log.traceId,
                hashChainValid: true,
                masked: false,
                tasksGenerated: [],
                detection: null,
                threatResponses: [{
                    responseId: "r1", eventName: "TEST", strategy: "NOTIFY_ONLY",
                    blocked: false, blockTarget: "", analyzed: false, riskLevel: "LOW", notified: true,
                }],
            };
        },
    };
}

function mockManagement(): ServerManagementTransport {
    return {
        approveTask: vi.fn(async () => ({ taskId: "t1", status: "dispatched" })),
        rejectTask: vi.fn(async () => ({ taskId: "t1", status: "rejected" })),
        getTaskStatus: vi.fn(async () => ({
            taskId: "t1", ruleId: "r1", eventName: "E", status: "dispatched",
            actionType: "A", severity: "HIGH", executionLevel: "AUTO",
            description: "d", sourceTraceId: "s", createdAt: "c", updatedAt: "u",
        })),
        listTasks: vi.fn(async () => ({ tasks: [], totalCount: 0 })),
        listPendingBlocks: vi.fn(async () => []),
        approveBlock: vi.fn(async () => ({ blockId: "b1", success: true, target: "t" })),
        rejectBlock: vi.fn(async () => ({ blockId: "b1", status: "rejected" })),
    };
}

// =========================================================================
// Matrix: all false (default) — local mode
// =========================================================================
describe("Integration config: all disabled (default)", () => {
    it("local mode works without any integration config", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({ message: "local only" });
        expect(result.traceId).toBeDefined();
        expect(result.threatResponses).toBeUndefined();
    });

    it("management API throws when all disabled", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        await expect(sentinel.approveTask("t", "a", "r")).rejects.toThrow("not enabled");
        await expect(sentinel.getTaskStatus("t")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// Matrix: threatResponseEnabled only
// =========================================================================
describe("Integration config: threatResponseEnabled=true only", () => {
    it("includes threatResponses from remote transport", async () => {
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { threatResponseEnabled: true } },
            { transport: { mode: "remote", transport: mockTransport() } },
        );
        const result = await sentinel.ingest({ message: "threat test" });
        expect(result.threatResponses).toBeDefined();
        expect(result.threatResponses!.length).toBe(1);
        expect(result.threatResponses![0].strategy).toBe("NOTIFY_ONLY");
    });

    it("management API still throws when only threatResponse is enabled", async () => {
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { threatResponseEnabled: true } },
        );
        await expect(sentinel.approveTask("t", "a", "r")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// Matrix: taskApprovalEnabled only
// =========================================================================
describe("Integration config: taskApprovalEnabled=true only", () => {
    it("approveTask works", async () => {
        const mgmt = mockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mgmt },
        );
        const result = await sentinel.approveTask("t1", "admin", "ok");
        expect(result.status).toBe("dispatched");
        expect(mgmt.approveTask).toHaveBeenCalledWith("t1", "admin", "ok");
    });

    it("getTaskStatus still throws (taskStatus not enabled)", async () => {
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskApprovalEnabled: true } },
            { management: mockManagement() },
        );
        await expect(sentinel.getTaskStatus("t1")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// Matrix: taskStatusEnabled only
// =========================================================================
describe("Integration config: taskStatusEnabled=true only", () => {
    it("getTaskStatus works", async () => {
        const mgmt = mockManagement();
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskStatusEnabled: true } },
            { management: mgmt },
        );
        const result = await sentinel.getTaskStatus("t1");
        expect(result.taskId).toBe("t1");
    });

    it("approveTask still throws (taskApproval not enabled)", async () => {
        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { taskStatusEnabled: true } },
            { management: mockManagement() },
        );
        await expect(sentinel.approveTask("t1", "a", "r")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// Matrix: all enabled
// =========================================================================
describe("Integration config: all enabled", () => {
    it("all features work together", async () => {
        const mgmt = mockManagement();
        const sentinel = Sentinel.initialize(
            {
                ...baseConfig,
                integration: {
                    configValidation: true,
                    threatResponseEnabled: true,
                    taskApprovalEnabled: true,
                    taskStatusEnabled: true,
                    syncDetectionRules: true,
                },
            },
            { transport: { mode: "remote", transport: mockTransport() }, management: mgmt },
        );

        // ingest: threatResponses included
        const ingestResult = await sentinel.ingest({ message: "full test" });
        expect(ingestResult.threatResponses).toBeDefined();

        // task approval
        const approveResult = await sentinel.approveTask("t1", "admin", "ok");
        expect(approveResult.status).toBe("dispatched");

        // task status
        const statusResult = await sentinel.getTaskStatus("t1");
        expect(statusResult.taskId).toBe("t1");

        // list tasks
        const listResult = await sentinel.listTasks({});
        expect(listResult.totalCount).toBe(0);

        // block management
        const blocks = await sentinel.listPendingBlocks();
        expect(blocks).toBeDefined();
    });
});

// =========================================================================
// Matrix: HMAC + hash chain
// =========================================================================
describe("Integration config: HMAC hash chain", () => {
    it("SHA-256 mode when hmacKey not set", async () => {
        const sentinel = Sentinel.initialize({
            ...baseConfig,
            security: { enableHashChain: true },
        });
        const result = await sentinel.ingest({ message: "sha256 test" });
        expect(result.hashChainValid).toBe(true);
    });

    it("HMAC mode when hmacKey is set", async () => {
        const sentinel = Sentinel.initialize({
            ...baseConfig,
            security: { enableHashChain: true, hmacKey: "hmac-key-32-bytes-long!!!!!!!!!!" },
        });
        const result = await sentinel.ingest({ message: "hmac test" });
        expect(result.hashChainValid).toBe(true);
    });

    it("hash chain disabled: no hash computed", async () => {
        const sentinel = Sentinel.initialize({
            ...baseConfig,
            security: { enableHashChain: false },
        });
        const result = await sentinel.ingest({ message: "no hash" });
        expect(result.hashChainValid).toBe(false);
    });
});

// =========================================================================
// Matrix: management transport without config flag
// =========================================================================
describe("Integration config: transport provided but flags disabled", () => {
    it("management transport provided but taskApproval disabled → error", async () => {
        const sentinel = Sentinel.initialize(
            baseConfig,
            { management: mockManagement() },
        );
        // transport exists but config flag is off
        await expect(sentinel.approveTask("t1", "a", "r")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// Matrix: onThreatResponse callback
// =========================================================================
describe("Integration config: onThreatResponse callback", () => {
    it("calls onThreatResponse when enabled and responses exist", async () => {
        const callback = vi.fn();
        const sentinel = Sentinel.initialize(
            {
                ...baseConfig,
                integration: { threatResponseEnabled: true },
                onThreatResponse: callback,
            },
            { transport: { mode: "remote", transport: mockTransport() } },
        );

        await sentinel.ingest({ message: "callback test" });
        expect(callback).toHaveBeenCalledTimes(1);
        expect(callback).toHaveBeenCalledWith([expect.objectContaining({ strategy: "NOTIFY_ONLY" })]);
    });

    it("does not call onThreatResponse when disabled", async () => {
        const callback = vi.fn();
        const sentinel = Sentinel.initialize(
            {
                ...baseConfig,
                onThreatResponse: callback,
            },
            { transport: { mode: "remote", transport: mockTransport() } },
        );

        await sentinel.ingest({ message: "no callback" });
        expect(callback).not.toHaveBeenCalled();
    });
});
