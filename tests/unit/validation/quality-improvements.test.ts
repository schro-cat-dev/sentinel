/**
 * Quality Improvement Tests (TDD)
 *
 * C-04: dual-mode transport error をcallerに通知
 * A-08: onTaskAction が解除関数を返す
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== C-04: dual-mode transport error notification =====
describe("C-04: dual-mode transport error in IngestionResult", () => {
    it("reports transport error in result when dual-mode transport fails", async () => {
        const mockTransport = {
            send: async () => { throw new Error("connection refused"); },
            close: async () => {},
        };

        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "dual", transport: mockTransport } },
        );

        const result = await sentinel.ingest({ message: "test", level: 3 });

        // Local processing should succeed
        expect(result.traceId).toBeDefined();
        // Transport error should be surfaced
        expect(result.transportError).toBeDefined();
        expect(result.transportError).toContain("connection refused");
    });

    it("no transportError when dual-mode transport succeeds", async () => {
        const mockTransport = {
            send: async () => ({
                traceId: "t", hashChainValid: false, tasksGenerated: [], masked: false, detection: null,
            }),
            close: async () => {},
        };

        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "dual", transport: mockTransport } },
        );

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.transportError).toBeUndefined();
    });

    it("no transportError in local mode", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.transportError).toBeUndefined();
    });
});

// ===== A-08: onTaskAction returns dispose function =====
describe("A-08: onTaskAction returns dispose function", () => {
    it("returns a function that unregisters the handler", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const handler = vi.fn();
        const dispose = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        expect(typeof dispose).toBe("function");
        dispose();

        // After dispose, handler should not be called on next dispatch
    });

    it("disposed handler is not called on subsequent ingest", async () => {
        const handler = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "r1",
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
                priority: 1,
                description: "test",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
        }));

        const dispose = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        dispose();

        await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });

        // Handler was disposed — should NOT have been called
        expect(handler).not.toHaveBeenCalled();
    });

    it("only the disposed handler is removed, others remain", async () => {
        const handler1 = vi.fn();
        const handler2 = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "r1",
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
                priority: 1,
                description: "test",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
        }));

        const dispose1 = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler1);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler2);
        dispose1();

        await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });

        expect(handler1).not.toHaveBeenCalled();
        expect(handler2).toHaveBeenCalled();
    });
});
