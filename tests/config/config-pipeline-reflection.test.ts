/**
 * Config → Pipeline Reflection Tests
 *
 * 各設定フィールドが実際のパイプライン動作に反映されることを検証。
 * 設定ON/OFF/各値の組合せで正常系・異常系・エッジケースをカバー。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig } from "../../src/index";
import { createTestTaskRule } from "../helpers/fixtures";
import type { SentinelConfig } from "../../src/configs/sentinel-config";
import type { Log } from "../../src/types/log";
import type { GeneratedTask, TaskResult } from "../../src/types/task";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ================================================================
// masking.enabled
// ================================================================
describe("masking.enabled reflection", () => {
    it("enabled=true masks PII in message", async () => {
        let captured: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: ["traceId"] },
            security: { enableHashChain: false },
            onLogProcessed: (log) => { captured = { ...log }; },
        }));

        await sentinel.ingest({ message: "Contact alice@secret.com", level: 3 });
        expect(captured).not.toBeNull();
        expect(captured!.message).not.toContain("alice@secret.com");
        expect(captured!.message).toContain("[MASKED_EMAIL]");
    });

    it("enabled=false passes PII through unmasked", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: false, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: [] },
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "Contact alice@secret.com", level: 3 });
        expect(result.masked).toBe(false);
    });

    it("enabled=true with no rules does not crash", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [], preserveFields: [] },
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.masked).toBe(true);
    });
});

// ================================================================
// masking.preserveFields
// ================================================================
describe("masking.preserveFields reflection", () => {
    it("preserves traceId from masking when listed", async () => {
        let captured: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: {
                enabled: true,
                rules: [{ type: "KEY_MATCH", sensitiveKeys: ["traceId"] }],
                preserveFields: ["traceId"],
            },
            security: { enableHashChain: false },
            onLogProcessed: (log) => { captured = { ...log }; },
        }));

        await sentinel.ingest({ message: "test", level: 3, traceId: "my-trace" });
        expect(captured!.traceId).toBe("my-trace");
    });

    it("masks traceId when NOT in preserveFields", async () => {
        let captured: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: {
                enabled: true,
                rules: [{ type: "KEY_MATCH", sensitiveKeys: ["traceId"] }],
                preserveFields: [],
            },
            security: { enableHashChain: false },
            onLogProcessed: (log) => { captured = { ...log }; },
        }));

        await sentinel.ingest({ message: "test", level: 3, traceId: "my-trace" });
        expect(captured!.traceId).toBe("[MASKED_KEY]");
    });
});

// ================================================================
// security.enableHashChain
// ================================================================
describe("security.enableHashChain reflection", () => {
    it("enabled=true produces hash and previousHash", async () => {
        let captured: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
            onLogProcessed: (log) => { captured = { ...log }; },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.hashChainValid).toBe(true);
        expect(captured!.hash).toBeDefined();
        expect(captured!.hash!.length).toBe(64);
        expect(captured!.previousHash).toBe("");
    });

    it("enabled=true chains hashes sequentially", async () => {
        const logs: Log[] = [];
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
            onLogProcessed: (log) => { logs.push({ ...log }); },
        }));

        await sentinel.ingest({ message: "first", level: 3 });
        await sentinel.ingest({ message: "second", level: 3 });
        await sentinel.ingest({ message: "third", level: 3 });

        expect(logs[0].previousHash).toBe("");
        expect(logs[1].previousHash).toBe(logs[0].hash);
        expect(logs[2].previousHash).toBe(logs[1].hash);
    });

    it("enabled=false skips hash computation", async () => {
        let captured: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: (log) => { captured = { ...log }; },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.hashChainValid).toBe(false);
        expect(captured!.hash).toBeUndefined();
    });
});

// ================================================================
// taskRules → detection → task generation
// ================================================================
describe("taskRules reflection", () => {
    it("generates task when matching rule exists for detected event", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                ruleId: "crit-1",
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
            })],
        }));

        const handler = vi.fn();
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        const result = await sentinel.ingest({ message: "failure", isCritical: true, level: 6 });
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(result.tasksGenerated[0].status).toBe("dispatched");
        expect(handler).toHaveBeenCalled();
    });

    it("does not generate task when no matching rule", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "COMPLIANCE_VIOLATION",
            })],
        }));

        const result = await sentinel.ingest({ message: "normal log", level: 3 });
        expect(result.tasksGenerated).toEqual([]);
    });

    it("empty taskRules never generates tasks", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated).toEqual([]);
        expect(result.detection?.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("multiple rules for same event produce multiple tasks", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [
                createTestTaskRule({ ruleId: "r1", eventName: "SYSTEM_CRITICAL_FAILURE", actionType: "SYSTEM_NOTIFICATION" }),
                createTestTaskRule({ ruleId: "r2", eventName: "SYSTEM_CRITICAL_FAILURE", actionType: "AI_ANALYZE" }),
            ],
        }));

        const result = await sentinel.ingest({ message: "failure", isCritical: true, level: 6 });
        expect(result.tasksGenerated.length).toBe(2);
    });

    it("severity threshold filters out low-severity rules", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [
                createTestTaskRule({ ruleId: "info-rule", eventName: "SYSTEM_CRITICAL_FAILURE", severity: "INFO" }),
                createTestTaskRule({ ruleId: "crit-rule", eventName: "SYSTEM_CRITICAL_FAILURE", severity: "CRITICAL" }),
            ],
        }));

        const result = await sentinel.ingest({ message: "failure", isCritical: true, level: 6 });
        // INFO rule should match (actual=CRITICAL >= rule=INFO), CRITICAL rule should also match
        expect(result.tasksGenerated.length).toBe(2);
    });
});

// ================================================================
// callbacks: onLogProcessed, onTaskGenerated, onTaskDispatched, onError
// ================================================================
describe("callback reflection", () => {
    it("onLogProcessed receives processed log with hash", async () => {
        const onLogProcessed = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
            onLogProcessed,
        }));

        await sentinel.ingest({ message: "test", level: 3 });
        expect(onLogProcessed).toHaveBeenCalledTimes(1);
        const log = onLogProcessed.mock.calls[0][0] as Log;
        expect(log.hash).toBeDefined();
        expect(log.message).toBe("test");
    });

    it("onTaskGenerated fires for each generated task", async () => {
        const onTaskGenerated = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [
                createTestTaskRule({ ruleId: "r1", eventName: "SYSTEM_CRITICAL_FAILURE" }),
                createTestTaskRule({ ruleId: "r2", eventName: "SYSTEM_CRITICAL_FAILURE" }),
            ],
            onTaskGenerated,
        }));

        await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(onTaskGenerated).toHaveBeenCalledTimes(2);
        const tasks = onTaskGenerated.mock.calls.map((c) => (c[0] as GeneratedTask).ruleId);
        expect(tasks).toContain("r1");
        expect(tasks).toContain("r2");
    });

    it("onTaskDispatched fires with dispatch result", async () => {
        const onTaskDispatched = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "SYSTEM_CRITICAL_FAILURE" })],
            onTaskDispatched,
        }));

        await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(onTaskDispatched).toHaveBeenCalledTimes(1);
        const result = onTaskDispatched.mock.calls[0][0] as TaskResult;
        expect(result.status).toBe("dispatched");
    });

    it("onError receives callback errors without breaking pipeline", async () => {
        const onError = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: () => { throw new Error("callback boom"); },
            onError,
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError.mock.calls[0][0].message).toBe("callback boom");
    });

    it("all callbacks undefined does not crash", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });
});

// ================================================================
// detection event types
// ================================================================
describe("detection event type reflection", () => {
    it("isCritical=true → SYSTEM_CRITICAL_FAILURE", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "boom", isCritical: true, level: 6 });
        expect(result.detection?.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("SECURITY type + level >= 5 → SECURITY_INTRUSION_DETECTED", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "intrusion", type: "SECURITY", level: 5 });
        expect(result.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");
    });

    it("COMPLIANCE + 'violation' → COMPLIANCE_VIOLATION", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "policy violation found", type: "COMPLIANCE", level: 4 });
        expect(result.detection?.eventName).toBe("COMPLIANCE_VIOLATION");
    });

    it("triggerAgent=true + level >= 4 → AI_ACTION_REQUIRED", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "needs AI", triggerAgent: true, level: 4 });
        expect(result.detection?.eventName).toBe("AI_ACTION_REQUIRED");
    });

    it("SLA + level >= 4 → SYSTEM_CRITICAL_FAILURE", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "SLA breach", type: "SLA", level: 4 });
        expect(result.detection?.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("normal log → no detection", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "normal operation", level: 3 });
        expect(result.detection).toBeNull();
    });

    it("AI_AGENT origin skipped (loop prevention)", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "from agent", origin: "AI_AGENT", level: 5, type: "SECURITY" });
        expect(result.detection).toBeNull();
    });

    it("AI_AGENT origin NOT skipped when isCritical", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "critical from agent", origin: "AI_AGENT", isCritical: true, level: 6 });
        expect(result.detection?.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });
});

// ================================================================
// execution levels + guardrails
// ================================================================
describe("execution level and guardrail reflection", () => {
    it("AUTO dispatches immediately", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "AUTO", guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 } })],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("dispatched");
    });

    it("MANUAL blocks for approval", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "MANUAL", guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 } })],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("blocked_approval");
    });

    it("MONITOR skips execution", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "MONITOR", guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 } })],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("skipped");
    });

    it("requireHumanApproval=true overrides AUTO to blocked", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "AUTO", guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 } })],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("blocked_approval");
    });

    it("SEMI_AUTO dispatches without confirm handler (backward compat)", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "SEMI_AUTO", guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 } })],
        }));

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("dispatched");
    });

    it("SEMI_AUTO blocks when confirm handler rejects", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ executionLevel: "SEMI_AUTO", guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 } })],
        }));
        sentinel.onTaskConfirm(async () => false);

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("blocked_approval");
    });

    it("timeoutMs causes failure when handler exceeds it", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                actionType: "SYSTEM_NOTIFICATION",
                guardrails: { requireHumanApproval: false, timeoutMs: 50, maxRetries: 0 },
            })],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {
            await new Promise((r) => setTimeout(r, 5000));
        });

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("failed");
        expect(result.tasksGenerated[0].error).toContain("timeout");
    });
});

// ================================================================
// combined config: masking + hash chain + tasks
// ================================================================
describe("combined config scenarios", () => {
    it("full pipeline: masking ON + hash chain ON + tasks ON", async () => {
        const logs: Log[] = [];
        const tasks: GeneratedTask[] = [];
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: ["traceId"] },
            security: { enableHashChain: true },
            taskRules: [createTestTaskRule({ eventName: "SYSTEM_CRITICAL_FAILURE" })],
            onLogProcessed: (log) => logs.push({ ...log }),
            onTaskGenerated: (task) => tasks.push({ ...task }),
        }));

        await sentinel.ingest({ message: "DB down. Contact admin@corp.com", isCritical: true, level: 6 });

        expect(logs).toHaveLength(1);
        expect(logs[0].message).not.toContain("admin@corp.com");
        expect(logs[0].hash).toBeDefined();
        expect(tasks).toHaveLength(1);
        expect(tasks[0].eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("minimal config: masking OFF + hash chain OFF + no tasks", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: false, rules: [], preserveFields: [] },
            security: { enableHashChain: false },
            taskRules: [],
        }));

        const result = await sentinel.ingest({ message: "simple log", level: 1 });
        expect(result.masked).toBe(false);
        expect(result.hashChainValid).toBe(false);
        expect(result.tasksGenerated).toEqual([]);
        expect(result.detection).toBeNull();
    });
});

// ================================================================
// logger injection
// ================================================================
describe("logger injection", () => {
    it("custom logger receives masking warnings", async () => {
        const logger = { warn: vi.fn(), error: vi.fn() };
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: [] },
            security: { enableHashChain: false },
            logger,
        }));

        // Normal operation should not produce warnings
        await sentinel.ingest({ message: "test@example.com", level: 3 });
        expect(logger.warn).not.toHaveBeenCalled();
    });
});

// ================================================================
// shutdown
// ================================================================
describe("shutdown lifecycle", () => {
    it("shutdown clears singleton", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
        }));

        await sentinel.shutdown();
        expect(() => Sentinel.getInstance()).toThrow("Sentinel must be initialized first");
    });

    it("can re-initialize after shutdown", async () => {
        const sentinel1 = Sentinel.initialize(createDefaultConfig({
            projectName: "p1", serviceId: "s1",
        }));
        await sentinel1.shutdown();

        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p2", serviceId: "s2",
        }));
        expect(sentinel2.getConfig().projectName).toBe("p2");
    });
});
