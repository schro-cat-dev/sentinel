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

    it("logs error when called in production environment", () => {
        const errorFn = vi.fn();
        Sentinel.initialize(defaultConfig({
            environment: "production",
            logger: { warn: vi.fn(), error: errorFn },
        }));
        Sentinel.reset();
        expect(errorFn).toHaveBeenCalledWith(
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

    it("handles transport close error gracefully (sync throw)", () => {
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

    it("handles transport close returning rejected promise (async .catch branch)", async () => {
        const transport = {
            send: vi.fn(),
            close: () => Promise.reject(new Error("async close failed")),
        };
        Sentinel.initialize(defaultConfig(), {
            transport: { mode: "local", transport },
        });
        // Should not throw — the .catch(() => {}) on line 104 swallows the rejection
        expect(() => Sentinel.reset()).not.toThrow();
        // Wait for the microtask queue to flush (the .catch runs asynchronously)
        await new Promise((resolve) => setTimeout(resolve, 50));
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

    // idempotent shutdown — see instance-lifecycle.test.ts A-03 for comprehensive tests
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

    it("remote mode with fallbackToLocal falls back on error and records transportError", async () => {
        const onErrorFn = vi.fn();
        const sendFn = vi.fn().mockRejectedValue(new Error("remote fail"));
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig({ onError: onErrorFn }), {
            transport: { mode: "remote", transport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(result.transportError).toBe("remote fail");
        // onError should have been called with the transport error
        expect(onErrorFn).toHaveBeenCalledWith(
            expect.objectContaining({ message: "remote fail" }),
            "transport.fallback",
        );
    });

    it("remote fallback onError callback throwing is caught silently", async () => {
        const sendFn = vi.fn().mockRejectedValue(new Error("remote fail"));
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig({
            onError: () => { throw new Error("onError boom in fallback"); },
        }), {
            transport: { mode: "remote", transport, fallbackToLocal: true },
        });

        // Should not throw despite onError throwing
        const result = await sentinel.ingest({ message: "fallback test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(result.transportError).toBe("remote fail");
    });

    it("remote fallback with non-Error rejection records stringified error", async () => {
        const sendFn = vi.fn().mockRejectedValue("string-rejection");
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "remote", transport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test", level: 3 });
        expect(result.transportError).toBe("string-rejection");
    });

    it("dual mode handles non-Error thrown from transport", async () => {
        const sendFn = vi.fn().mockRejectedValue("string-error");
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "dual", transport },
        });

        const result = await sentinel.ingest({ message: "non-error test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(result.transportError).toBe("string-error");
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
    // config freezing — see instance-lifecycle.test.ts A-04 for comprehensive tests

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
// Sentinel.onTaskConfirm
// =========================================================================
describe("Sentinel.onTaskConfirm", () => {
    it("registers a confirm handler on the task executor", () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const handler = vi.fn().mockReturnValue(true);
        // Should not throw
        expect(() => sentinel.onTaskConfirm(handler)).not.toThrow();
    });

    it("confirm handler that returns false blocks SEMI_AUTO task", async () => {
        const confirmHandler = vi.fn().mockReturnValue(false);
        const actionHandler = vi.fn();
        const sentinel = Sentinel.initialize(defaultConfig({
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "SEMI_AUTO",
            })],
        }));

        sentinel.onTaskConfirm(confirmHandler);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", actionHandler);

        await sentinel.ingest({
            message: "critical failure",
            isCritical: true,
            level: 6,
        });

        expect(confirmHandler).toHaveBeenCalled();
        // Handler should NOT be called because confirm returned false
        expect(actionHandler).not.toHaveBeenCalled();
    });
});

// =========================================================================
// sendWithTimeout — timer undefined branch
// =========================================================================
describe("Sentinel.sendWithTimeout — timer branch", () => {
    it("times out when transport send is slow", async () => {
        const sendFn = vi.fn().mockImplementation(
            () => new Promise((resolve) => setTimeout(resolve, 5000)),
        );
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "remote", transport, timeoutMs: 10, fallbackToLocal: false },
        });

        await expect(sentinel.ingest({ message: "slow send", level: 3 })).rejects.toThrow(
            "Transport timeout after 10ms",
        );
    });

    it("covers the finally branch where timer is defined (immediate resolve)", async () => {
        // Transport that resolves immediately — timer IS assigned (setTimeout is sync)
        // but the send resolves quickly. The finally block still runs clearTimeout.
        const sendFn = vi.fn().mockResolvedValue({
            traceId: "immediate-trace",
            tasksGenerated: [],
            detection: null,
            hashChainValid: false,
        });
        const transport = { send: sendFn, close: vi.fn() };
        const sentinel = Sentinel.initialize(defaultConfig(), {
            transport: { mode: "remote", transport, timeoutMs: 30000 },
        });

        const result = await sentinel.ingest({ message: "fast send", level: 3 });
        expect(result.traceId).toBe("immediate-trace");
        expect(sendFn).toHaveBeenCalled();
    });
});

// =========================================================================
// warnIfTooManyHandlers
// =========================================================================
describe("Sentinel.warnIfTooManyHandlers", () => {
    it("warns when more than 10 handlers are registered for same actionType", () => {
        const warnFn = vi.fn();
        const sentinel = Sentinel.initialize(defaultConfig({
            logger: { warn: warnFn, error: vi.fn() },
        }));

        // Register 11 handlers for the same actionType
        for (let i = 0; i < 11; i++) {
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());
        }

        expect(warnFn).toHaveBeenCalledWith(
            expect.stringContaining("11 handlers registered"),
            expect.objectContaining({ source: "sentinel" }),
        );
    });

    it("does not warn when 10 or fewer handlers are registered", () => {
        const warnFn = vi.fn();
        const sentinel = Sentinel.initialize(defaultConfig({
            logger: { warn: warnFn, error: vi.fn() },
        }));

        for (let i = 0; i < 10; i++) {
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());
        }

        expect(warnFn).not.toHaveBeenCalled();
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

// =========================================================================
// taskTransports 統合
// =========================================================================
describe("Sentinel: taskTransports integration", () => {
    it("passes taskTransports to TaskExecutor and dispatches on event", async () => {
        const dispatchFn = vi.fn().mockResolvedValue({ transportName: "mock", success: true });
        const transport = { name: "mock", dispatch: dispatchFn };

        const taskRule = createTestTaskRule();
        const config = defaultConfig({
            taskRules: [taskRule],
            detectionRules: [{
                ruleId: "det-transport-verify",
                eventName: taskRule.eventName,
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            whitelist: { level: "off" },
        });

        const sentinel = Sentinel.initialize(config, { taskTransports: [transport] });
        const result = await sentinel.ingest({ message: "critical failure", level: 6, type: "SYSTEM", isCritical: true });

        // isCritical=true + level 6 で検知ルールがマッチし、タスクが生成される
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // トランスポートにdispatchが実際に呼ばれたことを検証
        expect(dispatchFn).toHaveBeenCalledTimes(result.tasksGenerated.length);
        // 受け取ったタスクのeventNameが正しいこと
        const receivedTask = dispatchFn.mock.calls[0][0];
        expect(receivedTask.eventName).toBe(taskRule.eventName);
    });

    it("shutdown calls closeTransports", async () => {
        const closeFn = vi.fn().mockResolvedValue(undefined);
        const transport = {
            name: "closeable",
            dispatch: vi.fn().mockResolvedValue({ transportName: "closeable", success: true }),
            close: closeFn,
        };

        const sentinel = Sentinel.initialize(defaultConfig(), { taskTransports: [transport] });
        await sentinel.shutdown();

        expect(closeFn).toHaveBeenCalledTimes(1);
    });

    it("shutdown tolerates transport close errors", async () => {
        const transport = {
            name: "failing-close",
            dispatch: vi.fn().mockResolvedValue({ transportName: "failing-close", success: true }),
            close: vi.fn().mockRejectedValue(new Error("close failed")),
        };

        const sentinel = Sentinel.initialize(defaultConfig(), { taskTransports: [transport] });

        // エラーでクラッシュしない
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
    });

    it("works without taskTransports option (backward compat)", async () => {
        const sentinel = Sentinel.initialize(defaultConfig());
        const result = await sentinel.ingest({ message: "test", level: 3 });

        expect(result.traceId).toBeDefined();
    });

    it("works with empty taskTransports array", async () => {
        const sentinel = Sentinel.initialize(defaultConfig(), { taskTransports: [] });
        const result = await sentinel.ingest({ message: "test", level: 3 });

        expect(result.traceId).toBeDefined();
    });

    it("reset cleans up taskTransports (best-effort close)", async () => {
        const closeFn = vi.fn().mockResolvedValue(undefined);
        const transport = {
            name: "resettable",
            dispatch: vi.fn().mockResolvedValue({ transportName: "resettable", success: true }),
            close: closeFn,
        };

        Sentinel.initialize(defaultConfig(), { taskTransports: [transport] });
        Sentinel.reset();

        // closeTransports() は async だが reset() から fire-and-forget で呼ばれる
        // マイクロタスクキューを flush して close の呼び出しを確認
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(closeFn).toHaveBeenCalled();
    });

    it("auto-creates console transport from config and dispatches to it", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const taskRule = createTestTaskRule();
        const config = defaultConfig({
            taskRules: [taskRule],
            taskTransportConfigs: [
                { name: "auto-console", type: "console", enabled: true },
            ],
            detectionRules: [{
                ruleId: "det-auto-console",
                eventName: taskRule.eventName,
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            whitelist: { level: "off" },
        });

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "auto console test", level: 6, type: "SYSTEM", isCritical: true });

        // isCritical=true + level 6 でタスク生成を保証
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // ConsoleTaskTransport の dispatch により console.info が呼ばれる
        expect(infoSpy).toHaveBeenCalled();
        const output = JSON.parse(infoSpy.mock.calls[0][0] as string);
        expect(output.sentinel_task.eventName).toBe(taskRule.eventName);
        infoSpy.mockRestore();
    });

    it("merges user-injected and config-based transports", async () => {
        const userDispatch = vi.fn().mockResolvedValue({ transportName: "user", success: true });
        const userTransport = { name: "user", dispatch: userDispatch };
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const taskRule = createTestTaskRule();
        const config = defaultConfig({
            taskRules: [taskRule],
            taskTransportConfigs: [
                { name: "auto-console", type: "console", enabled: true },
            ],
            detectionRules: [{
                ruleId: "det-merge",
                eventName: taskRule.eventName,
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            whitelist: { level: "off" },
        });

        const sentinel = Sentinel.initialize(config, { taskTransports: [userTransport] });
        const result = await sentinel.ingest({ message: "merge test", level: 6, type: "SYSTEM", isCritical: true });

        // タスク生成を保証
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // user-injected と config-based の両方が実行される（条件なし）
        expect(userDispatch).toHaveBeenCalled();
        expect(infoSpy).toHaveBeenCalled();
        infoSpy.mockRestore();
    });

    it("config-based disabled transport does not dispatch", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const taskRule = createTestTaskRule();
        const config = defaultConfig({
            taskRules: [taskRule],
            taskTransportConfigs: [
                { name: "disabled-console", type: "console", enabled: false },
            ],
            detectionRules: [{
                ruleId: "det-disabled",
                eventName: taskRule.eventName,
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            whitelist: { level: "off" },
        });

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "disabled test", level: 6, type: "SYSTEM", isCritical: true });

        // タスクは生成されるが、disabled console transport には dispatch されない
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(infoSpy).not.toHaveBeenCalled();
        infoSpy.mockRestore();
    });

    it("E2E: ingest → event detection → task generation → transport dispatch", async () => {
        const dispatchFn = vi.fn().mockResolvedValue({
            transportName: "e2e-transport",
            success: true,
            externalId: "ticket-001",
        });
        const transport = { name: "e2e-transport", dispatch: dispatchFn };

        const taskRule = createTestTaskRule();
        const config = defaultConfig({
            taskRules: [taskRule],
            detectionRules: [{
                ruleId: "det-e2e",
                eventName: taskRule.eventName,
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            whitelist: { level: "off" },
        });

        const sentinel = Sentinel.initialize(config, { taskTransports: [transport] });

        // isCritical=true + level 6 で確実に検知→タスク生成→トランスポート配信
        const result = await sentinel.ingest({ message: "E2E critical event", level: 6, type: "SYSTEM", isCritical: true });

        expect(result.traceId).toBeDefined();
        // 条件分岐なし — タスク生成を保証
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(dispatchFn).toHaveBeenCalled();
        const receivedTask = dispatchFn.mock.calls[0][0];
        expect(receivedTask.eventName).toBe(taskRule.eventName);
        expect(receivedTask.actionType).toBe(taskRule.actionType);
        expect(receivedTask.sourceLog.message).toBe("E2E critical event");
    });

    it("double shutdown with transports is idempotent", async () => {
        const closeFn = vi.fn().mockResolvedValue(undefined);
        const transport = {
            name: "double-close",
            dispatch: vi.fn().mockResolvedValue({ transportName: "double-close", success: true }),
            close: closeFn,
        };

        const sentinel = Sentinel.initialize(defaultConfig(), { taskTransports: [transport] });
        await sentinel.shutdown();
        await sentinel.shutdown(); // 2回目 — isShutdown ガードで何もしない

        expect(closeFn).toHaveBeenCalledTimes(1);
    });

    it("initialize with invalid http_webhook endpoint in config throws", () => {
        expect(() => Sentinel.initialize(defaultConfig({
            taskTransportConfigs: [
                { name: "bad", type: "http_webhook", enabled: true, endpoint: "https://192.168.1.1/hook" },
            ],
        }))).toThrow();
    });

    it("shutdown closes both user-injected and config-created transports", async () => {
        const userClose = vi.fn().mockResolvedValue(undefined);
        const userTransport = {
            name: "user",
            dispatch: vi.fn().mockResolvedValue({ transportName: "user", success: true }),
            close: userClose,
        };

        const config = defaultConfig({
            taskTransportConfigs: [
                { name: "auto-console", type: "console", enabled: true },
            ],
        });

        const sentinel = Sentinel.initialize(config, { taskTransports: [userTransport] });
        await sentinel.shutdown();

        // user-injected transport の close が呼ばれること
        expect(userClose).toHaveBeenCalledTimes(1);
        // config-based console transport の close も呼ばれる（ConsoleTaskTransport.close は no-op だがエラーなし）
    });

    it("config-based http_webhook with disabled flag is not instantiated (SSRF endpoint allowed)", () => {
        // 同じ endpoint を enabled: true で渡すと SSRF で throw する
        expect(() => Sentinel.initialize(defaultConfig({
            taskTransportConfigs: [
                { name: "bad-enabled", type: "http_webhook", enabled: true, endpoint: "https://192.168.1.1/hook" },
            ],
        }))).toThrow();
        Sentinel.reset();

        // enabled: false → factory がスキップするのでインスタンス化されず、SSRF チェックも走らない
        expect(() => Sentinel.initialize(defaultConfig({
            taskTransportConfigs: [
                { name: "bad-but-disabled", type: "http_webhook", enabled: false, endpoint: "https://192.168.1.1/hook" },
            ],
        }))).not.toThrow();
    });
});
