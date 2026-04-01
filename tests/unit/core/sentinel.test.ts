/**
 * Sentinel Class Unit Tests
 *
 * 既存のinstance-lifecycle.testを補完し、パブリックAPI全体をカバーする。
 * 対象: initialize, getInstance, reset, shutdown, ingest, onTaskAction,
 *        onTaskConfirm, updateCallbacks, getConfig
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";
import type { SentinelConfig } from "../../../src/configs/sentinel-config";

function defaultConfig(overrides: Partial<SentinelConfig> = {}): SentinelConfig {
    return createDefaultConfig({
        projectName: "sentinel-test",
        serviceId: "test-svc",
        environment: "test",
        security: { enableHashChain: false },
        ...overrides,
    });
}

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// =========================================================================
// Sentinel.initialize
// =========================================================================
describe("Sentinel.initialize", () => {
    it("returns a Sentinel instance on first call", () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        expect(sentinel).toBeInstanceOf(Sentinel);
    });

    it("returns existing instance on duplicate initialize and logs warning", () => {
        const warnFn = vi.fn();
        const config = defaultConfig({ logger: { warn: warnFn, error: vi.fn() } });
        const first = Sentinel.initialize(config);
        const second = Sentinel.initialize(config);
        expect(second).toBe(first);
        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("already initialized"),
            expect.objectContaining({ source: "sentinel" }),
        );
    });

    it("second initialize uses existing instance's logger if new config has none", () => {
        const warnFn = vi.fn();
        const config1 = defaultConfig({ logger: { warn: warnFn, error: vi.fn() } });
        Sentinel.initialize(config1);

        // Second call with different config (no logger)
        const config2 = defaultConfig();
        Sentinel.initialize(config2);

        // Should have used first instance's logger
        expect(warnFn).toHaveBeenCalled();
    });
});

// =========================================================================
// Sentinel.getInstance
// =========================================================================
describe("Sentinel.getInstance", () => {
    it("throws when not initialized", () => {
        expect(() => Sentinel.getInstance()).toThrow("Sentinel must be initialized first");
    });

    it("returns instance after initialization", () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        expect(Sentinel.getInstance()).toBe(sentinel);
    });
});

// =========================================================================
// Sentinel.reset
// =========================================================================
describe("Sentinel.reset", () => {
    it("clears singleton so getInstance throws", () => {
        Sentinel.initialize(defaultConfig());
        Sentinel.reset();
        expect(() => Sentinel.getInstance()).toThrow();
    });

    it("warns when called in non-test environment", () => {
        const warnFn = vi.fn();
        Sentinel.initialize(defaultConfig({
            environment: "production",
            logger: { warn: warnFn, error: vi.fn() },
        }));
        Sentinel.reset();
        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("production"),
            expect.objectContaining({ source: "sentinel" }),
        );
    });

    it("does not warn in test environment", () => {
        const warnFn = vi.fn();
        Sentinel.initialize(defaultConfig({
            environment: "test",
            logger: { warn: warnFn, error: vi.fn() },
        }));
        Sentinel.reset();
        expect(warnFn).not.toHaveBeenCalled();
    });

    it("is safe to call when no instance exists", () => {
        expect(() => Sentinel.reset()).not.toThrow();
    });

    it("handles transport close error gracefully", () => {
        const transport = {
            send: vi.fn(),
            close: () => { throw new Error("close failed"); },
        };
        Sentinel.initialize(defaultConfig(), {
            transport: { mode: "local", transport },
        });
        // Should not throw
        expect(() => Sentinel.reset()).not.toThrow();
    });
});

// =========================================================================
// Sentinel.shutdown
// =========================================================================
describe("Sentinel.shutdown", () => {
    it("prevents subsequent ingest calls", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        await sentinel.shutdown();
        await expect(sentinel.ingest({ message: "after shutdown" })).rejects.toThrow("shutdown");
    });

    it("clears singleton reference", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        await sentinel.shutdown();
        expect(() => Sentinel.getInstance()).toThrow();
    });

    it("handles transport close error gracefully", async () => {
        const transport = {
            send: vi.fn(),
            close: async () => { throw new Error("transport close boom"); },
        };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "local", transport },
        });
        // Should not throw
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
    });
});

// =========================================================================
// Sentinel.ingest
// =========================================================================
describe("Sentinel.ingest", () => {
    it("returns result with traceId", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const result = await sentinel.ingest({ message: "hello", level: 3 });
        expect(typeof result.traceId).toBe("string");
        expect(result.traceId.length).toBeGreaterThan(0);
    });

    it("throws on invalid input (missing message)", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        await expect(sentinel.ingest({} as never)).rejects.toThrow();
    });

    it("local mode processes without transport", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const result = await sentinel.ingest({ message: "local test" });
        expect(result.traceId).toBeDefined();
    });

    it("dual mode sends to transport and processes locally", async () => {
        const sendFn = vi.fn().mockResolvedValue({ traceId: "remote-trace", tasksGenerated: [], detection: null });
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "dual", transport },
        });

        const result = await sentinel.ingest({ message: "dual test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(sendFn).toHaveBeenCalled();
    });

    it("dual mode falls back gracefully on transport error", async () => {
        const sendFn = vi.fn().mockRejectedValue(new Error("network fail"));
        const transport = { send: sendFn, close: vi.fn() };
        const onErrorFn = vi.fn();
        const sentinel = Sentinel.initialize(
            defaultConfig({ onError: onErrorFn }),
            { transport: { mode: "dual", transport } },
        );

        const result = await sentinel.ingest({ message: "fallback test", level: 3 });
        // Local processing should still succeed
        expect(result.traceId).toBeDefined();
        expect(result.transportError).toBe("network fail");
    });

    it("remote mode with fallbackToLocal falls back on error", async () => {
        const sendFn = vi.fn().mockRejectedValue(new Error("remote fail"));
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "remote", transport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test", level: 3 });
        expect(result.traceId).toBeDefined();
    });

    it("remote mode without fallback rethrows transport error", async () => {
        const sendFn = vi.fn().mockRejectedValue(new Error("remote fail"));
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "remote", transport, fallbackToLocal: false },
        });

        await expect(sentinel.ingest({ message: "no fallback", level: 3 })).rejects.toThrow("remote fail");
    });
});

// =========================================================================
// Sentinel.onTaskAction
// =========================================================================
describe("Sentinel.onTaskAction", () => {
    it("registers handler and returns deregistration function", () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const handler = vi.fn();
        const deregister = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        expect(typeof deregister).toBe("function");
        deregister();
        // No throw after deregister
    });

    it("throws after shutdown", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        await sentinel.shutdown();
        expect(() => sentinel.onTaskAction("TEST", vi.fn())).toThrow("shutdown");
    });

    it("dispatches to registered handler on matching task", async () => {
        const handler = vi.fn().mockResolvedValue(undefined);
        const sentinel = Sentinel.initialize(defaultConfig({
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
            })],
        }));

        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        await sentinel.ingest({
            message: "critical failure",
            isCritical: true,
            level: 6,
        });

        expect(handler).toHaveBeenCalled();
    });
});

// =========================================================================
// Sentinel.updateCallbacks
// =========================================================================
describe("Sentinel.updateCallbacks", () => {
    it("updates onLogProcessed callback", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const cb = vi.fn();
        sentinel.updateCallbacks({ onLogProcessed: cb });

        await sentinel.ingest({ message: "callback test", level: 3 });
        expect(cb).toHaveBeenCalled();
    });

    it("clears callback with null", async () => {
        const cb = vi.fn();
        const sentinel = Sentinel.initialize(defaultConfig({ onLogProcessed: cb }));

        await sentinel.ingest({ message: "first" });
        expect(cb).toHaveBeenCalledTimes(1);

        sentinel.updateCallbacks({ onLogProcessed: null });
        await sentinel.ingest({ message: "second" });
        expect(cb).toHaveBeenCalledTimes(1); // not called again
    });

    it("throws after shutdown", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        await sentinel.shutdown();
        expect(() => sentinel.updateCallbacks({})).toThrow("shutdown");
    });
});

// =========================================================================
// Sentinel.getConfig
// =========================================================================
describe("Sentinel.getConfig", () => {
    it("returns frozen config", () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const cfg = sentinel.getConfig();
        expect(Object.isFrozen(cfg)).toBe(true);
    });

    it("reflects initialization values", () => {
        const sentinel = Sentinel.initialize(defaultConfig({
            projectName: "my-project",
            serviceId: "my-svc",
        }));
        const cfg = sentinel.getConfig();
        expect(cfg.projectName).toBe("my-project");
        expect(cfg.serviceId).toBe("my-svc");
    });
});

// =========================================================================
// Error escalation depth (onError + callback throws)
// =========================================================================
describe("Error escalation safety", () => {
    it("onLogProcessed + onError both throwing does not crash or loop", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sentinel = Sentinel.initialize(defaultConfig({
            onLogProcessed: () => { throw new Error("callback boom"); },
            onError: () => { throw new Error("onError boom"); },
        }));

        // パイプライン自体はクラッシュしない
        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();

        // onError例外はconsole.errorに記録される
        expect(stderrSpy).toHaveBeenCalled();
        stderrSpy.mockRestore();
    });

    it("multiple failing callbacks do not cause infinite recursion", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        let callCount = 0;
        const sentinel = Sentinel.initialize(defaultConfig({
            onLogProcessed: () => { callCount++; throw new Error("processed boom"); },
            onTaskGenerated: () => { callCount++; throw new Error("generated boom"); },
            onError: () => { callCount++; throw new Error("error boom"); },
            taskRules: [createTestTaskRule()],
        }));

        await sentinel.ingest({
            message: "critical failure",
            isCritical: true,
            level: 6,
        });

        // コールバックは呼ばれたが、無限ループしていない（callCountが制限内）
        expect(callCount).toBeLessThan(50);
        stderrSpy.mockRestore();
    });

    it("concurrent ingests with throwing callbacks all complete", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sentinel = Sentinel.initialize(defaultConfig({
            onLogProcessed: () => { throw new Error("concurrent boom"); },
            onError: () => { /* swallow */ },
        }));

        const results = await Promise.all(
            Array.from({ length: 20 }, (_, i) =>
                sentinel.ingest({ message: `concurrent ${i}`, level: 3 }),
            ),
        );

        // 全20件が完了
        expect(results).toHaveLength(20);
        for (const r of results) {
            expect(r.traceId).toBeDefined();
        }
        stderrSpy.mockRestore();
    });
});
