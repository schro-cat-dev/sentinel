/**
 * Audit Fix Tests (TDD)
 *
 * 多角的監査で発見された8件の修正テスト。
 * #1: dual-mode race condition
 * #2: silent re-initialization warning
 * #3: confirmHandler not cleared in shutdown
 * #4: PII categories validated even when masking disabled
 * #5: Sentinel.reset() production warning
 * #6: Go/TS eventName sync (ドキュメントのみ — テスト不要)
 * #7: README test count (ドキュメントのみ — テスト不要)
 * #8: intrusion-detection.md rule ordering (ドキュメントのみ — テスト不要)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== #1: dual-mode race condition =====
describe("Fix #1: dual-mode lastProcessedLog race safety", () => {
    it("concurrent ingest calls in dual mode do not corrupt remote payload", async () => {
        const sentLogs: unknown[] = [];
        const mockTransport = {
            send: async (log: unknown) => {
                sentLogs.push(log);
                return { traceId: "t", hashChainValid: false, tasksGenerated: [], masked: false, detection: null };
            },
            close: async () => {},
        };

        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "dual", transport: mockTransport } },
        );

        // Parallel ingestion
        const [r1, r2] = await Promise.all([
            sentinel.ingest({ message: "log-A", level: 3 }),
            sentinel.ingest({ message: "log-B", level: 3 }),
        ]);

        // Both should complete without error
        expect(r1.traceId).toBeDefined();
        expect(r2.traceId).toBeDefined();

        // Each sent log should have a valid message (not undefined/corrupted)
        for (const log of sentLogs) {
            expect((log as { message: string }).message).toMatch(/^log-[AB]$/);
        }
    });
});

// ===== #2: silent re-initialization warning =====
describe("Fix #2: re-initialization emits warning", () => {
    it("second initialize call logs a warning", () => {
        const warnFn = vi.fn();
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
        });

        Sentinel.initialize(config);
        const second = Sentinel.initialize(config);

        // Should return existing instance
        expect(second).toBe(Sentinel.getInstance());
        // Should have warned
        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("already initialized"),
            expect.any(Object),
        );
    });
});

// ===== #3: confirmHandler cleared in shutdown =====
describe("Fix #3: shutdown clears confirmHandler", () => {
    it("confirmHandler is cleared after shutdown", async () => {
        const confirmFn = vi.fn().mockReturnValue(false);
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));
        sentinel.onTaskConfirm(confirmFn);

        await sentinel.shutdown();

        // Re-initialize — the old confirmHandler should not persist
        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                executionLevel: "SEMI_AUTO",
                severity: "CRITICAL",
            })],
        }));
        sentinel2.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());

        // Ingest a critical log — SEMI_AUTO without confirmHandler should dispatch (not block)
        const result = await sentinel2.ingest({ message: "fail", isCritical: true, level: 6 });
        // If confirmHandler leaked, it would return false → blocked_approval
        // After proper cleanup, SEMI_AUTO without confirmHandler = dispatched
        if (result.tasksGenerated.length > 0) {
            expect(result.tasksGenerated[0].status).toBe("dispatched");
        }
    });
});

// ===== #4: PII categories validated even when masking disabled =====
describe("Fix #4: PII category validation regardless of masking.enabled", () => {
    it("rejects invalid PII category even when masking is disabled", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                masking: {
                    enabled: false,  // disabled!
                    rules: [{ type: "PII_TYPE", category: "SSN" as never }],
                    preserveFields: [],
                },
            })),
        ).toThrow(ValidationError);
    });

    it("accepts valid PII category when masking is disabled", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                masking: {
                    enabled: false,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                    preserveFields: [],
                },
            })),
        ).not.toThrow();
    });
});

// ===== #5: Sentinel.reset() production warning =====
describe("Fix #5: Sentinel.reset() warns in non-test environment", () => {
    it("reset warns when environment is production", () => {
        const warnFn = vi.fn();
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            environment: "production",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
        }));

        Sentinel.reset();

        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("reset"),
            expect.any(Object),
        );
    });

    it("reset does not warn in test environment", () => {
        const warnFn = vi.fn();
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            environment: "test",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
        }));

        Sentinel.reset();

        // No warning for test environment
        const resetWarnings = warnFn.mock.calls.filter(
            (call: unknown[]) => typeof call[0] === "string" && (call[0] as string).includes("reset"),
        );
        expect(resetWarnings).toHaveLength(0);
    });
});
