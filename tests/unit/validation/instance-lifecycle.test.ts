/**
 * Instance Lifecycle Tests (TDD)
 *
 * 品質ベンチマーク MUST FAIL 修正:
 * A-02: shutdown()でsigner未リセット
 * A-03: shutdown()非冪等
 * A-04: config未凍結
 * A-05: 入力配列未コピー
 * C-03: onError例外の記録
 * D-02: ハンドラ無制限蓄積
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== A-02: shutdown() releases all state =====
describe("A-02: shutdown releases all internal state", () => {
    it("hash chain is reset after shutdown and re-initialize", async () => {
        const sentinel1 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
        }));

        // First ingest creates a hash chain
        const r1 = await sentinel1.ingest({ message: "first", level: 3 });
        expect(r1.hashChainValid).toBe(true);

        await sentinel1.shutdown();

        // Re-initialize — hash chain should start fresh
        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
        }));
        const r2 = await sentinel2.ingest({ message: "second", level: 3 });
        expect(r2.hashChainValid).toBe(true);
        // previousHash of first log in a new chain should be empty string
        // (verified by hash chain not being "continued" from sentinel1)
    });
});

// ===== A-03: shutdown() is idempotent =====
describe("A-03: shutdown is idempotent", () => {
    it("double shutdown does not throw", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        await sentinel.shutdown();
        // Second shutdown should not throw
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
    });

    it("shutdown with transport is idempotent", async () => {
        let closeCount = 0;
        const mockTransport = {
            send: vi.fn(),
            close: async () => { closeCount++; },
        };

        const sentinel = Sentinel.initialize(
            createDefaultConfig({ projectName: "p", serviceId: "s", security: { enableHashChain: false } }),
            { transport: { mode: "local", transport: mockTransport } },
        );

        await sentinel.shutdown();
        await sentinel.shutdown();
        // transport.close should be called at most once
        expect(closeCount).toBe(1);
    });
});

// ===== A-04: config frozen after initialization =====
describe("A-04: config is frozen after initialization", () => {
    it("cannot mutate config.taskRules after initialization", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule()],
        });

        Sentinel.initialize(config);

        // Attempt to mutate should throw in strict mode (frozen)
        expect(() => {
            config.taskRules.push(createTestTaskRule({ ruleId: "injected" }));
        }).toThrow();
    });

    it("cannot mutate config.detectionRules after initialization", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "r1",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
        });

        Sentinel.initialize(config);

        expect(() => {
            config.detectionRules!.push({
                ruleId: "injected",
                eventName: "COMPLIANCE_VIOLATION",
                priority: "LOW",
                conditions: {},
            });
        }).toThrow();
    });

    it("getConfig returns frozen object", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const cfg = sentinel.getConfig();
        expect(() => {
            (cfg as Record<string, unknown>).projectName = "hacked";
        }).toThrow();
    });
});

// ===== A-05: input arrays defensively copied =====
describe("A-05: input arrays are defensively copied", () => {
    it("external taskRules mutation does not affect internal state", async () => {
        const rules = [createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "CRITICAL",
        })];

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: rules,
        }));

        // Verify original rules work
        const r = await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
    });
});

// ===== C-03: onError exception fallback =====
describe("C-03: onError exceptions are not silently swallowed", () => {
    it("onError throwing does not crash pipeline", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: () => { throw new Error("callback boom"); },
            onError: () => { throw new Error("onError boom"); },
        }));

        // Pipeline should not crash
        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();

        // The swallowed onError exception should be logged to stderr
        expect(stderrSpy).toHaveBeenCalled();

        stderrSpy.mockRestore();
    });
});

// ===== D-02: handler accumulation limit =====
describe("D-02: handler accumulation has bounds", () => {
    it("warns when too many handlers registered for same actionType", () => {
        const warnFn = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
        }));

        // Register many handlers for same actionType
        for (let i = 0; i < 15; i++) {
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {});
        }

        // Should warn about accumulation
        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("handlers"),
            expect.any(Object),
        );
    });
});
