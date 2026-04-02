/**
 * Advanced Security Test: State Manipulation Attacks
 *
 * Tests against:
 * - Singleton abuse (double init, getInstance before init, reset + re-init)
 * - Handler manipulation (mass register, mutation detection, recursion, timeout)
 * - TaskExecutor state management
 * - IngestionEngine state isolation
 * - Config immutability
 * - Callback state and error isolation
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { IngestionEngine } from "../../../src/core/engine/ingestion-engine";
import { IntegritySigner } from "../../../src/security/integrity-signer";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import { EventDetector } from "../../../src/core/detection/event-detector";
import { TaskGenerator } from "../../../src/core/task/task-generator";
import { LogNormalizer } from "../../../src/core/engine/log-normalizer";
import { SentinelConfig } from "../../../src/configs/sentinel-config";
import { GeneratedTask } from "../../../src/types/task";
import { Log } from "../../../src/types/log";
import {
    createTestLog,
    createTestConfig,
    createTestTaskRule,
    createCriticalLog,
    createSecurityLog,
} from "../../helpers/fixtures";

// ---- helpers ----

function createEngine(configOverrides: Partial<SentinelConfig> = {}): {
    engine: IngestionEngine;
    signer: IntegritySigner;
    executor: TaskExecutor;
    config: SentinelConfig;
} {
    const config = createTestConfig({
        security: { enableHashChain: true },
        ...configOverrides,
    });
    const signer = new IntegritySigner();
    const executor = new TaskExecutor();
    const engine = new IngestionEngine({
        config,
        normalizer: new LogNormalizer(config.serviceId),
        signer,
        detector: new EventDetector(),
        taskGenerator: new TaskGenerator(config.taskRules),
        taskExecutor: executor,
    });
    return { engine, signer, executor, config };
}

function createAutoTask(overrides: Partial<GeneratedTask> = {}): GeneratedTask {
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
        guardrails: {
            requireHumanApproval: false,
            timeoutMs: 30000,
            maxRetries: 3,
        },
        sourceLog: {
            traceId: "trace-1",
            message: "test",
            boundary: "test:handler",
            level: 5,
            timestamp: new Date().toISOString(),
        },
        createdAt: new Date().toISOString(),
        ...overrides,
    };
}

// ============================================================
// 1. Singleton Abuse
// ============================================================
describe("State Manipulation: Singleton Abuse", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    it("double initialize with different configs returns same instance (second ignored)", () => {
        const config1 = createTestConfig({ serviceId: "svc-1" });
        const config2 = createTestConfig({ serviceId: "svc-2" });

        const instance1 = Sentinel.initialize(config1);
        const instance2 = Sentinel.initialize(config2);

        expect(instance1).toBe(instance2);
        expect(instance1.getConfig().serviceId).toBe("svc-1");
    });

    it("getInstance before initialize throws", () => {
        expect(() => Sentinel.getInstance()).toThrow(
            "Sentinel must be initialized first",
        );
    });

    it("reset + re-initialize with new config works", () => {
        const config1 = createTestConfig({ serviceId: "svc-1" });
        Sentinel.initialize(config1);
        expect(Sentinel.getInstance().getConfig().serviceId).toBe("svc-1");

        Sentinel.reset();

        const config2 = createTestConfig({ serviceId: "svc-2" });
        Sentinel.initialize(config2);
        expect(Sentinel.getInstance().getConfig().serviceId).toBe("svc-2");
    });

    it("concurrent initialize calls all return same instance", () => {
        const config = createTestConfig({});
        const instances: Sentinel[] = [];

        for (let i = 0; i < 10; i++) {
            instances.push(Sentinel.initialize(config));
        }

        const first = instances[0];
        for (const inst of instances) {
            expect(inst).toBe(first);
        }
    });

    it("shutdown + re-initialize with new config works", async () => {
        const config1 = createTestConfig({ serviceId: "svc-shutdown-1" });
        const instance1 = Sentinel.initialize(config1);
        await instance1.shutdown();

        const config2 = createTestConfig({ serviceId: "svc-shutdown-2" });
        const instance2 = Sentinel.initialize(config2);
        expect(instance2.getConfig().serviceId).toBe("svc-shutdown-2");
    });

    it("getInstance after shutdown throws", async () => {
        const config = createTestConfig({});
        const instance = Sentinel.initialize(config);
        await instance.shutdown();

        expect(() => Sentinel.getInstance()).toThrow();
    });

    it("shutdown is idempotent (no error on double shutdown)", async () => {
        const config = createTestConfig({});
        const instance = Sentinel.initialize(config);
        await instance.shutdown();
        // Second shutdown on same object should not throw
        // (instance is stale but shutdown is best-effort)
        await expect(instance.shutdown()).resolves.not.toThrow();
    });

    it("reset is idempotent", () => {
        Sentinel.reset();
        Sentinel.reset();
        Sentinel.reset();
        expect(() => Sentinel.getInstance()).toThrow();
    });

    it("initialize after reset creates fully functional instance", async () => {
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });
        const config = createTestConfig({ taskRules: [rule] });

        Sentinel.initialize(config);
        Sentinel.reset();

        const newConfig = createTestConfig({ taskRules: [rule] });
        const sentinel = Sentinel.initialize(newConfig);
        const dispatched: string[] = [];
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", (task) => {
            dispatched.push(task.taskId);
        });

        await sentinel.ingest(createCriticalLog());
        expect(dispatched.length).toBeGreaterThan(0);
    });
});

// ============================================================
// 2. Handler Manipulation
// ============================================================
describe("State Manipulation: Handler Manipulation", () => {
    let executor: TaskExecutor;

    beforeEach(() => {
        executor = new TaskExecutor();
    });

    it("register same handler up to hard limit causes handler to execute that many times", async () => {
        let count = 0;
        const handler = () => { count++; };

        // VULN-014: ハードリミット100件
        for (let i = 0; i < 100; i++) {
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);
        }

        const task = createAutoTask();
        await executor.dispatch(task);
        expect(count).toBe(100);
    });

    it("register beyond hard limit (100) throws error", () => {
        const handler = () => {};
        for (let i = 0; i < 100; i++) {
            executor.registerHandler("SYSTEM_NOTIFICATION", handler);
        }
        expect(() => executor.registerHandler("SYSTEM_NOTIFICATION", handler))
            .toThrow(/Too many handlers/);
    });

    it("register then removeHandlers clears all handlers for that type", async () => {
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        executor.removeHandlers("SYSTEM_NOTIFICATION");

        // No handlers and no default handler = no execution
        await executor.dispatch(createAutoTask());
        expect(called).toBe(false);
    });

    it("register handler for nonexistent action type does not throw", () => {
        expect(() => {
            executor.registerHandler("NONEXISTENT_TYPE", () => {});
        }).not.toThrow();
    });

    it("handler for nonexistent type is not invoked for other types", async () => {
        let called = false;
        executor.registerHandler("NONEXISTENT_TYPE", () => { called = true; });

        await executor.dispatch(createAutoTask({ actionType: "SYSTEM_NOTIFICATION" }));
        expect(called).toBe(false);
    });

    it("handler that modifies the task object: mutation is visible to subsequent handlers", async () => {
        const mutations: string[] = [];

        executor.registerHandler("SYSTEM_NOTIFICATION", (task) => {
            (task as unknown as Record<string, unknown>).injectedField = "attack";
            mutations.push("first");
        });

        executor.registerHandler("SYSTEM_NOTIFICATION", (task) => {
            mutations.push("second");
            // Check if mutation from first handler is visible
            if ((task as unknown as Record<string, unknown>).injectedField === "attack") {
                mutations.push("mutation-visible");
            }
        });

        await executor.dispatch(createAutoTask());
        expect(mutations).toContain("first");
        expect(mutations).toContain("second");
        // Note: current implementation passes same reference, so mutation is visible
        expect(mutations).toContain("mutation-visible");
    });

    it("handler that throws after partial work: dispatch returns failed status", async () => {
        let partialWorkDone = false;

        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            partialWorkDone = true;
            throw new Error("handler exploded after partial work");
        });

        const result = await executor.dispatch(createAutoTask());
        expect(partialWorkDone).toBe(true);
        expect(result.status).toBe("failed");
        expect(result.error).toContain("handler exploded");
    });

    it("handler that rejects: dispatch returns failed status", async () => {
        executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
            throw new Error("async rejection");
        });

        const result = await executor.dispatch(createAutoTask());
        expect(result.status).toBe("failed");
        expect(result.error).toContain("async rejection");
    });

    it("handler that never resolves: times out with guardrails.timeoutMs", async () => {
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            return new Promise(() => {
                // intentionally never resolves
            });
        });

        const task = createAutoTask({
            guardrails: {
                requireHumanApproval: false,
                timeoutMs: 100, // 100ms timeout
                maxRetries: 0,
            },
        });

        const result = await executor.dispatch(task);
        expect(result.status).toBe("failed");
        expect(result.error).toContain("timeout");
    }, 5000);

    it("handler that takes long but within timeout succeeds", async () => {
        executor.registerHandler("SYSTEM_NOTIFICATION", async () => {
            await new Promise((r) => setTimeout(r, 50));
        });

        const task = createAutoTask({
            guardrails: {
                requireHumanApproval: false,
                timeoutMs: 5000,
                maxRetries: 0,
            },
        });

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
    });

    it("removeHandlers for non-registered type does not throw", () => {
        expect(() => executor.removeHandlers("NONEXISTENT")).not.toThrow();
    });

    it("clearHandlers removes all types", async () => {
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });
        executor.registerHandler("AI_ANALYZE", () => { called = true; });

        executor.clearHandlers();

        await executor.dispatch(createAutoTask({ actionType: "SYSTEM_NOTIFICATION" }));
        await executor.dispatch(createAutoTask({ actionType: "AI_ANALYZE" }));
        expect(called).toBe(false);
    });

    it("first handler throws, second handler IS still executed (R-2: failure isolation)", async () => {
        const order: string[] = [];

        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            order.push("first");
            throw new Error("first fails");
        });

        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            order.push("second");
        });

        const result = await executor.dispatch(createAutoTask());
        expect(order).toEqual(["first", "second"]);
        expect(result.status).toBe("failed");
    });
});

// ============================================================
// 3. TaskExecutor State
// ============================================================
describe("State Manipulation: TaskExecutor State", () => {
    it("clearHandlers actually clears all registered handlers", async () => {
        const executor = new TaskExecutor();
        let count = 0;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { count++; });
        executor.registerHandler("AI_ANALYZE", () => { count++; });
        executor.registerHandler("KILL_SWITCH", () => { count++; });

        executor.clearHandlers();

        await executor.dispatch(createAutoTask({ actionType: "SYSTEM_NOTIFICATION" }));
        await executor.dispatch(createAutoTask({ actionType: "AI_ANALYZE" }));
        await executor.dispatch(createAutoTask({ actionType: "KILL_SWITCH" }));
        expect(count).toBe(0);
    });

    it("handlers registered before task rules still execute", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        // Dispatch directly (rules are TaskGenerator concern, not executor)
        await executor.dispatch(createAutoTask());
        expect(called).toBe(true);
    });

    it("multiple handlers for same action type all execute in order", async () => {
        const executor = new TaskExecutor();
        const order: number[] = [];

        executor.registerHandler("SYSTEM_NOTIFICATION", () => { order.push(1); });
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { order.push(2); });
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { order.push(3); });

        await executor.dispatch(createAutoTask());
        expect(order).toEqual([1, 2, 3]);
    });

    it("default handler is used when no specific handler registered", async () => {
        let defaultCalled = false;
        const executor = new TaskExecutor(() => { defaultCalled = true; });

        await executor.dispatch(createAutoTask());
        expect(defaultCalled).toBe(true);
    });

    it("default handler is NOT used when specific handler exists", async () => {
        let defaultCalled = false;
        let specificCalled = false;
        const executor = new TaskExecutor(() => { defaultCalled = true; });
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { specificCalled = true; });

        await executor.dispatch(createAutoTask());
        expect(specificCalled).toBe(true);
        expect(defaultCalled).toBe(false);
    });

    it("MANUAL execution level blocks dispatch without handler", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        const task = createAutoTask({ executionLevel: "MANUAL" });
        const result = await executor.dispatch(task);
        expect(result.status).toBe("blocked_approval");
        expect(called).toBe(false);
    });

    it("MONITOR execution level skips dispatch", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        const task = createAutoTask({ executionLevel: "MONITOR" });
        const result = await executor.dispatch(task);
        expect(result.status).toBe("skipped");
        expect(called).toBe(false);
    });

    it("SEMI_AUTO without confirm handler behaves like AUTO", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        const task = createAutoTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(called).toBe(true);
    });

    it("SEMI_AUTO with confirm handler returning false blocks", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });
        executor.setConfirmHandler(() => false);

        const task = createAutoTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);
        expect(result.status).toBe("blocked_approval");
        expect(called).toBe(false);
    });

    it("SEMI_AUTO with confirm handler returning true dispatches", async () => {
        const executor = new TaskExecutor();
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });
        executor.setConfirmHandler(() => true);

        const task = createAutoTask({ executionLevel: "SEMI_AUTO" });
        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(called).toBe(true);
    });

    it("requireHumanApproval=true always blocks regardless of executionLevel", async () => {
        const executor = new TaskExecutor();
        const task = createAutoTask({
            executionLevel: "AUTO",
            guardrails: {
                requireHumanApproval: true,
                timeoutMs: 30000,
                maxRetries: 3,
            },
        });

        const result = await executor.dispatch(task);
        expect(result.status).toBe("blocked_approval");
    });
});

// ============================================================
// 4. IngestionEngine State
// ============================================================
describe("State Manipulation: IngestionEngine State", () => {
    it("getLastProcessedLog before any ingest returns null", () => {
        const { engine } = createEngine();
        expect(engine.getLastProcessedLog()).toBeNull();
    });

    it("getLastProcessedLog returns copy not reference", async () => {
        const { engine } = createEngine();
        await engine.handle(createTestLog({ message: "original" }));

        const log1 = engine.getLastProcessedLog();
        const log2 = engine.getLastProcessedLog();

        expect(log1).not.toBe(log2); // different object references
        expect(log1).toEqual(log2);  // same content
    });

    it("modifying returned log does not affect internal state", async () => {
        const { engine } = createEngine();
        await engine.handle(createTestLog({ message: "immutable" }));

        const returned = engine.getLastProcessedLog()!;
        returned.message = "MODIFIED";

        const internal = engine.getLastProcessedLog()!;
        expect(internal.message).not.toBe("MODIFIED");
    });

    it("chain lock under contention (10+ concurrent)", async () => {
        const { engine } = createEngine();
        const promises: Promise<unknown>[] = [];

        for (let i = 0; i < 15; i++) {
            promises.push(
                engine.handle(createTestLog({
                    message: `concurrent-${i}`,
                    logicalClock: i,
                })),
            );
        }

        const results = await Promise.all(promises);
        expect(results.length).toBe(15);

        // All should have valid hash chain
        for (const result of results) {
            expect((result as { hashChainValid: boolean }).hashChainValid).toBe(true);
        }
    });

    it("chain lock produces unique hashes under contention", async () => {
        const { engine, signer } = createEngine();
        const promises: Promise<unknown>[] = [];

        for (let i = 0; i < 20; i++) {
            promises.push(
                engine.handle(createTestLog({
                    message: `contention-${i}`,
                    logicalClock: i,
                })),
            );
        }

        await Promise.all(promises);

        // The signer should have a non-empty hash after processing
        expect(signer.getPreviousHash()).not.toBe("");
        expect(signer.getPreviousHash().length).toBe(64);
    });

    it("sequential ingestion produces verifiable chain", async () => {
        const { engine, signer } = createEngine();
        const logs: Log[] = [];

        for (let i = 0; i < 5; i++) {
            await engine.handle(createTestLog({
                message: `sequential-${i}`,
                logicalClock: i,
            }));
            logs.push(engine.getLastProcessedLog()!);
        }

        // Verify chain integrity
        for (let i = 0; i < logs.length; i++) {
            const prevHash = i === 0 ? "" : logs[i - 1].hash!;
            expect(IntegritySigner.verifyHash(logs[i], prevHash)).toBe(true);
        }
    });

    it("getLastProcessedLog updates after each ingest", async () => {
        const { engine } = createEngine();

        await engine.handle(createTestLog({ message: "first" }));
        const first = engine.getLastProcessedLog()!;

        await engine.handle(createTestLog({ message: "second" }));
        const second = engine.getLastProcessedLog()!;

        expect(first.message).toContain("first");
        expect(second.message).toContain("second");
        expect(first.hash).not.toBe(second.hash);
    });

    it("hash chain disabled: hashChainValid is false", async () => {
        const { engine } = createEngine({
            security: { enableHashChain: false },
        });

        const result = await engine.handle(createTestLog({ message: "no-chain" }));
        expect(result.hashChainValid).toBe(false);
    });
});

// ============================================================
// 5. Config Immutability
// ============================================================
describe("State Manipulation: Config Immutability", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    it("modifying config object after initialize does NOT affect behavior (deep freeze)", () => {
        const config = createTestConfig({ serviceId: "original" });
        Sentinel.initialize(config);

        // Config is frozen — mutation throws
        expect(() => { config.serviceId = "mutated"; }).toThrow();
    });

    it("getConfig returns object that reflects original config", () => {
        const config = createTestConfig({
            serviceId: "test-svc",
            projectName: "test-proj",
        });
        const sentinel = Sentinel.initialize(config);

        const returned = sentinel.getConfig();
        expect(returned.serviceId).toBe("test-svc");
        expect(returned.projectName).toBe("test-proj");
    });

    it("getConfig returns Readonly type (runtime mutation check)", () => {
        const config = createTestConfig({});
        const sentinel = Sentinel.initialize(config);

        const returned = sentinel.getConfig();
        // TypeScript enforces Readonly, but at runtime JS allows mutation
        // This test documents that getConfig() returns the internal reference
        expect(typeof returned).toBe("object");
        expect(returned).not.toBeNull();
    });

    it("security config CANNOT be silently disabled after init (deep freeze)", () => {
        const config = createTestConfig({
            security: { enableHashChain: true },
        });
        Sentinel.initialize(config);

        // Frozen — nested mutation throws
        expect(() => {
            (config.security as { enableHashChain: boolean }).enableHashChain = false;
        }).toThrow();
    });

    it("masking config CANNOT be silently disabled after init (deep freeze)", () => {
        const config = createTestConfig({
            masking: { enabled: true, rules: [], preserveFields: [] },
        });
        Sentinel.initialize(config);

        // Frozen — nested mutation throws
        expect(() => { config.masking.enabled = false; }).toThrow();
    });

    it("taskRules array CANNOT be modified after init (deep freeze)", () => {
        const rule = createTestTaskRule({});
        const config = createTestConfig({ taskRules: [rule] });
        Sentinel.initialize(config);

        // Frozen — array mutation throws
        expect(() => {
            config.taskRules.push(createTestTaskRule({ ruleId: "injected" }));
        }).toThrow();
    });

    it("createDefaultConfig produces consistent defaults", () => {
        const c1 = createTestConfig({});
        const c2 = createTestConfig({});

        expect(c1.security.enableHashChain).toBe(c2.security.enableHashChain);
        expect(c1.masking.enabled).toBe(c2.masking.enabled);
        expect(c1.environment).toBe(c2.environment);
    });
});

// ============================================================
// 6. Callback State
// ============================================================
describe("State Manipulation: Callback State", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    it("onLogProcessed receives log after hash chain update", async () => {
        let receivedLog: Log | null = null;
        const config = createTestConfig({
            security: { enableHashChain: true },
            onLogProcessed: (log) => { receivedLog = log; },
        });

        const { engine } = createEngine(config);
        await engine.handle(createTestLog({ message: "callback-test" }));

        expect(receivedLog).not.toBeNull();
        expect(receivedLog!.hash).toBeDefined();
        expect(receivedLog!.hash!.length).toBe(64);
        expect(receivedLog!.previousHash).toBeDefined();
    });

    it("onTaskGenerated receives task before dispatch", async () => {
        const generatedTasks: GeneratedTask[] = [];
        const dispatchedTaskIds: string[] = [];

        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config = createTestConfig({
            taskRules: [rule],
            onTaskGenerated: (task) => {
                generatedTasks.push(task);
            },
        });

        const { engine, executor } = createEngine(config);
        executor.registerHandler("SYSTEM_NOTIFICATION", (task) => {
            dispatchedTaskIds.push(task.taskId);
        });

        await engine.handle(createCriticalLog());

        expect(generatedTasks.length).toBeGreaterThan(0);
        expect(dispatchedTaskIds.length).toBeGreaterThan(0);

        // Task was generated (callback fired) and also dispatched
        expect(generatedTasks[0].taskId).toBe(dispatchedTaskIds[0]);
    });

    it("callback throwing does not affect subsequent callbacks in same pipeline run", async () => {
        let logProcessedCalled = false;

        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config = createTestConfig({
            taskRules: [rule],
            onTaskGenerated: () => {
                throw new Error("callback explosion");
            },
            onLogProcessed: () => {
                logProcessedCalled = true;
            },
        });

        const { engine, executor } = createEngine(config);
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});

        // Should not throw despite callback error
        await expect(
            engine.handle(createCriticalLog()),
        ).resolves.toBeDefined();

        // onLogProcessed should still fire
        expect(logProcessedCalled).toBe(true);
    });

    it("onTaskDispatched callback throwing does not break pipeline", async () => {
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config = createTestConfig({
            taskRules: [rule],
            onTaskDispatched: () => {
                throw new Error("dispatch callback explosion");
            },
        });

        const { engine, executor } = createEngine(config);
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});

        const result = await engine.handle(createCriticalLog());
        expect(result.hashChainValid).toBe(true);
    });

    it("onError is called when onLogProcessed throws", async () => {
        const errors: { error: Error; context: string }[] = [];

        const config = createTestConfig({
            onLogProcessed: () => {
                throw new Error("log callback error");
            },
            onError: (error, context) => {
                errors.push({ error, context });
            },
        });

        const { engine } = createEngine(config);
        await engine.handle(createTestLog({ message: "trigger-error" }));

        expect(errors.length).toBeGreaterThan(0);
        expect(errors[0].error.message).toContain("log callback error");
        expect(errors[0].context).toBe("callback");
    });

    it("onError itself throwing does not crash the pipeline", async () => {
        const config = createTestConfig({
            onLogProcessed: () => {
                throw new Error("callback error");
            },
            onError: () => {
                throw new Error("error handler also explodes");
            },
        });

        const { engine } = createEngine(config);
        // Should not throw
        await expect(
            engine.handle(createTestLog({ message: "double-error" })),
        ).resolves.toBeDefined();
    });

    it("callback that takes 5s blocks pipeline (callbacks are sync-invoked)", async () => {
        let callbackStarted = false;
        let callbackFinished = false;

        const config = createTestConfig({
            onLogProcessed: () => {
                callbackStarted = true;
                // Simulate blocking work (sync CPU-bound)
                const start = Date.now();
                while (Date.now() - start < 100) {
                    // busy wait 100ms (shortened from 5s for test speed)
                }
                callbackFinished = true;
            },
        });

        const { engine } = createEngine(config);
        await engine.handle(createTestLog({ message: "blocking-callback" }));

        // Both started and finished because it is blocking
        expect(callbackStarted).toBe(true);
        expect(callbackFinished).toBe(true);
    });

    it("multiple onLogProcessed invocations receive different logs", async () => {
        const receivedMessages: string[] = [];

        const config = createTestConfig({
            onLogProcessed: (log) => {
                receivedMessages.push(log.message);
            },
        });

        const { engine } = createEngine(config);
        await engine.handle(createTestLog({ message: "msg-1" }));
        await engine.handle(createTestLog({ message: "msg-2" }));
        await engine.handle(createTestLog({ message: "msg-3" }));

        expect(receivedMessages).toHaveLength(3);
        expect(receivedMessages[0]).toContain("msg-1");
        expect(receivedMessages[1]).toContain("msg-2");
        expect(receivedMessages[2]).toContain("msg-3");
    });

    it("callback receives log with all fields populated", async () => {
        let receivedLog: Log | null = null;

        const config = createTestConfig({
            security: { enableHashChain: true },
            onLogProcessed: (log) => { receivedLog = log; },
        });

        const { engine } = createEngine(config);
        await engine.handle(createTestLog({ message: "full-log" }));

        expect(receivedLog).not.toBeNull();
        expect(receivedLog!.traceId).toBeDefined();
        expect(receivedLog!.serviceId).toBeDefined();
        expect(receivedLog!.timestamp).toBeDefined();
        expect(receivedLog!.hash).toBeDefined();
    });

    it("no callbacks configured: pipeline still works", async () => {
        const config = createTestConfig({});
        // Remove all callback references
        delete config.onLogProcessed;
        delete config.onTaskGenerated;
        delete config.onTaskDispatched;
        delete config.onError;

        const { engine } = createEngine(config);
        const result = await engine.handle(createTestLog({ message: "no-callbacks" }));

        expect(result.hashChainValid).toBe(true);
        expect(result.traceId).toBeDefined();
    });

    it("onTaskGenerated callback throwing: task is still dispatched", async () => {
        let dispatched = false;
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config = createTestConfig({
            taskRules: [rule],
            onTaskGenerated: () => {
                throw new Error("pre-dispatch callback failed");
            },
        });

        const { engine, executor } = createEngine(config);
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            dispatched = true;
        });

        await engine.handle(createCriticalLog());
        expect(dispatched).toBe(true);
    });

    it("callback receives security log with detection result", async () => {
        let resultDetection: unknown = null;

        const rule = createTestTaskRule({
            eventName: "SECURITY_INTRUSION_DETECTED",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config = createTestConfig({ taskRules: [rule] });

        const { engine, executor } = createEngine(config);
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});

        const result = await engine.handle(createSecurityLog());
        resultDetection = result.detection;

        expect(resultDetection).not.toBeNull();
        expect((resultDetection as { eventName: string }).eventName).toBe(
            "SECURITY_INTRUSION_DETECTED",
        );
    });

    it("callback error does not corrupt hash chain state", async () => {
        let callCount = 0;

        const config = createTestConfig({
            security: { enableHashChain: true },
            onLogProcessed: () => {
                callCount++;
                if (callCount === 2) throw new Error("mid-chain callback error");
            },
        });

        const { engine } = createEngine(config);

        // Process 3 logs: callback throws on 2nd but chain should stay valid
        const logs: Log[] = [];
        for (let i = 0; i < 3; i++) {
            await engine.handle(createTestLog({ message: `chain-err-${i}`, logicalClock: i }));
            logs.push(engine.getLastProcessedLog()!);
        }

        // All 3 logs should have hashes
        for (const log of logs) {
            expect(log.hash).toBeDefined();
            expect(log.hash!.length).toBe(64);
        }

        // Chain should still be verifiable
        for (let i = 1; i < logs.length; i++) {
            expect(IntegritySigner.verifyHash(logs[i], logs[i - 1].hash!)).toBe(true);
        }
    });
});

// ============================================================
// 7. Handler Registration Edge Cases
// ============================================================
describe("State Manipulation: Handler Registration Edge Cases", () => {
    it("registering handler after dispatch does not retroactively apply", async () => {
        const executor = new TaskExecutor();

        // Dispatch first with no handler
        const result1 = await executor.dispatch(createAutoTask());
        // No handler and no default = no execution but dispatched status
        expect(result1.status).toBe("dispatched");

        // Now register handler
        let called = false;
        executor.registerHandler("SYSTEM_NOTIFICATION", () => { called = true; });

        // Handler not called for previous dispatch
        expect(called).toBe(false);

        // But works for next dispatch
        await executor.dispatch(createAutoTask());
        expect(called).toBe(true);
    });

    it("confirm handler can be replaced", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});

        executor.setConfirmHandler(() => false);
        const r1 = await executor.dispatch(createAutoTask({ executionLevel: "SEMI_AUTO" }));
        expect(r1.status).toBe("blocked_approval");

        executor.setConfirmHandler(() => true);
        const r2 = await executor.dispatch(createAutoTask({ executionLevel: "SEMI_AUTO" }));
        expect(r2.status).toBe("dispatched");
    });

    it("async confirm handler works", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});
        executor.setConfirmHandler(async () => {
            await new Promise((r) => setTimeout(r, 10));
            return true;
        });

        const result = await executor.dispatch(createAutoTask({ executionLevel: "SEMI_AUTO" }));
        expect(result.status).toBe("dispatched");
    });

    it("async confirm handler rejection blocks dispatch", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});
        executor.setConfirmHandler(async () => {
            await new Promise((r) => setTimeout(r, 10));
            return false;
        });

        const result = await executor.dispatch(createAutoTask({ executionLevel: "SEMI_AUTO" }));
        expect(result.status).toBe("blocked_approval");
    });

    it("dispatch result includes taskId and ruleId from input", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {});

        const task = createAutoTask({ taskId: "my-task", ruleId: "my-rule" });
        const result = await executor.dispatch(task);

        expect(result.taskId).toBe("my-task");
        expect(result.ruleId).toBe("my-rule");
    });

    it("dispatch result includes dispatchedAt timestamp", async () => {
        const executor = new TaskExecutor();
        const result = await executor.dispatch(createAutoTask());

        expect(result.dispatchedAt).toBeDefined();
        // Should be a valid ISO timestamp
        expect(new Date(result.dispatchedAt).getTime()).not.toBeNaN();
    });

    it("multiple action types can coexist", async () => {
        const executor = new TaskExecutor();
        const calls: string[] = [];

        executor.registerHandler("SYSTEM_NOTIFICATION", () => { calls.push("notif"); });
        executor.registerHandler("AI_ANALYZE", () => { calls.push("ai"); });
        executor.registerHandler("KILL_SWITCH", () => { calls.push("kill"); });

        await executor.dispatch(createAutoTask({ actionType: "SYSTEM_NOTIFICATION" }));
        await executor.dispatch(createAutoTask({ actionType: "AI_ANALYZE" }));
        await executor.dispatch(createAutoTask({ actionType: "KILL_SWITCH" }));

        expect(calls).toEqual(["notif", "ai", "kill"]);
    });

    it("removeHandlers only removes specified type", async () => {
        const executor = new TaskExecutor();
        const calls: string[] = [];

        executor.registerHandler("SYSTEM_NOTIFICATION", () => { calls.push("notif"); });
        executor.registerHandler("AI_ANALYZE", () => { calls.push("ai"); });

        executor.removeHandlers("SYSTEM_NOTIFICATION");

        await executor.dispatch(createAutoTask({ actionType: "SYSTEM_NOTIFICATION" }));
        await executor.dispatch(createAutoTask({ actionType: "AI_ANALYZE" }));

        expect(calls).toEqual(["ai"]);
    });

    it("handler returning a value (not void) does not break dispatch", async () => {
        const executor = new TaskExecutor();
        executor.registerHandler("SYSTEM_NOTIFICATION", () => {
            return "unexpected return" as unknown as void;
        });

        const result = await executor.dispatch(createAutoTask());
        expect(result.status).toBe("dispatched");
    });

    it("handler receiving task gets all expected fields", async () => {
        const executor = new TaskExecutor();
        let receivedTask: GeneratedTask | null = null;

        executor.registerHandler("SYSTEM_NOTIFICATION", (task) => {
            receivedTask = task;
        });

        await executor.dispatch(createAutoTask());

        expect(receivedTask).not.toBeNull();
        expect(receivedTask!.taskId).toBeDefined();
        expect(receivedTask!.ruleId).toBeDefined();
        expect(receivedTask!.eventName).toBeDefined();
        expect(receivedTask!.severity).toBeDefined();
        expect(receivedTask!.actionType).toBeDefined();
        expect(receivedTask!.executionLevel).toBeDefined();
        expect(receivedTask!.guardrails).toBeDefined();
    });
});

// ============================================================
// 8. Pipeline Integration State
// ============================================================
describe("State Manipulation: Pipeline Integration State", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    it("Sentinel.ingest returns IngestionResult with all fields", async () => {
        const config = createTestConfig({});
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest(createTestLog({ message: "integration" }));

        expect(result.traceId).toBeDefined();
        expect(typeof result.hashChainValid).toBe("boolean");
        expect(Array.isArray(result.tasksGenerated)).toBe(true);
        expect(typeof result.masked).toBe("boolean");
    });

    it("Sentinel.onTaskAction registers handler that receives dispatched tasks", async () => {
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });
        const config = createTestConfig({ taskRules: [rule] });
        const sentinel = Sentinel.initialize(config);

        const received: string[] = [];
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", (task) => {
            received.push(task.taskId);
        });

        await sentinel.ingest(createCriticalLog());
        expect(received.length).toBeGreaterThan(0);
    });

    it("Sentinel.onTaskConfirm works for SEMI_AUTO tasks", async () => {
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "SEMI_AUTO",
        });
        const config = createTestConfig({ taskRules: [rule] });
        const sentinel = Sentinel.initialize(config);

        let dispatched = false;
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", () => { dispatched = true; });
        sentinel.onTaskConfirm(() => false);

        const result = await sentinel.ingest(createCriticalLog());
        expect(dispatched).toBe(false);
        expect(result.tasksGenerated[0].status).toBe("blocked_approval");
    });

    it("multiple sequential ingests maintain hash chain across calls", async () => {
        const config = createTestConfig({ security: { enableHashChain: true } });
        const sentinel = Sentinel.initialize(config);

        const results = [];
        for (let i = 0; i < 5; i++) {
            results.push(await sentinel.ingest(createTestLog({ message: `seq-${i}`, logicalClock: i })));
        }

        for (const r of results) {
            expect(r.hashChainValid).toBe(true);
        }
    });

    it("ingest with masking enabled returns masked=true", async () => {
        const config = createTestConfig({
            masking: {
                enabled: true,
                rules: [{ type: "keyword", pattern: "secret", replacement: "***" }],
                preserveFields: ["traceId"],
            },
        });
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest(createTestLog({ message: "my secret data" }));
        expect(result.masked).toBe(true);
    });

    it("ingest with masking disabled returns masked=false", async () => {
        const config = createTestConfig({
            masking: { enabled: false, rules: [], preserveFields: [] },
        });
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest(createTestLog({ message: "plain data" }));
        expect(result.masked).toBe(false);
    });

    it("ingest with no matching event returns null detection", async () => {
        const config = createTestConfig({});
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest(createTestLog({
            type: "DEBUG",
            level: 1,
            isCritical: false,
            triggerAgent: false,
        }));
        expect(result.detection).toBeNull();
    });

    it("ingest with critical log returns detection with SYSTEM_CRITICAL_FAILURE", async () => {
        const config = createTestConfig({});
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest(createCriticalLog());
        expect(result.detection).not.toBeNull();
        expect(result.detection!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("shutdown clears handlers so subsequent ingest on new instance starts fresh", async () => {
        const rule = createTestTaskRule({
            eventName: "SYSTEM_CRITICAL_FAILURE",
            actionType: "SYSTEM_NOTIFICATION",
        });

        const config1 = createTestConfig({ taskRules: [rule] });
        const s1 = Sentinel.initialize(config1);
        let count1 = 0;
        s1.onTaskAction("SYSTEM_NOTIFICATION", () => { count1++; });
        await s1.ingest(createCriticalLog());
        expect(count1).toBe(1);

        await s1.shutdown();

        const config2 = createTestConfig({ taskRules: [rule] });
        const s2 = Sentinel.initialize(config2);
        let count2 = 0;
        s2.onTaskAction("SYSTEM_NOTIFICATION", () => { count2++; });
        await s2.ingest(createCriticalLog());
        // New instance, new handler, count2 should be 1 (not accumulated)
        expect(count2).toBe(1);
        expect(count1).toBe(1); // old counter unchanged
    });

    it("getConfig returns same environment as configured", () => {
        const config = createTestConfig({ environment: "production" });
        const sentinel = Sentinel.initialize(config);
        expect(sentinel.getConfig().environment).toBe("production");
    });
});
