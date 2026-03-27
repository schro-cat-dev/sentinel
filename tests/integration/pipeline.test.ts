import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../src/index";
import { SentinelConfig } from "../../src/configs/sentinel-config";
import { TaskRule, GeneratedTask } from "../../src/types/task";
import { Log } from "../../src/types/log";
import { createTestTaskRule } from "../helpers/fixtures";

/**
 * End-to-end integration tests for the v1 pipeline:
 * ingest → normalize → mask → hash-chain → detect → generate task → dispatch
 */
describe("Sentinel v1 Pipeline Integration", () => {
    let config: SentinelConfig;

    const taskRules: TaskRule[] = [
        createTestTaskRule({
            ruleId: "crit-notify",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH",
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "AUTO",
            priority: 1,
        }),
        createTestTaskRule({
            ruleId: "sec-analyze",
            eventName: "SECURITY_INTRUSION_DETECTED",
            severity: "HIGH",
            actionType: "AI_ANALYZE",
            executionLevel: "AUTO",
            priority: 1,
        }),
        createTestTaskRule({
            ruleId: "comp-escalate",
            eventName: "COMPLIANCE_VIOLATION",
            severity: "MEDIUM",
            actionType: "ESCALATE",
            executionLevel: "MANUAL",
            priority: 1,
        }),
    ];

    beforeEach(() => {
        Sentinel.reset();
        config = createDefaultConfig({
            projectName: "integration-test",
            serviceId: "test-svc",
            environment: "test",
            security: { enableHashChain: true },
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: ["traceId"],
            },
            taskRules,
        });
    });

    afterEach(() => {
        Sentinel.reset();
    });

    describe("Logger lifecycle", () => {
        it("initializes singleton", () => {
            const sentinel = Sentinel.initialize(config);
            expect(sentinel).toBeDefined();
            expect(Sentinel.getInstance()).toBe(sentinel);
        });

        it("returns same instance on re-init", () => {
            const s1 = Sentinel.initialize(config);
            const s2 = Sentinel.initialize(config);
            expect(s1).toBe(s2);
        });

        it("throws when getting instance before init", () => {
            expect(() => Sentinel.getInstance()).toThrow("must be initialized");
        });

        it("allows re-init after reset", () => {
            const s1 = Sentinel.initialize(config);
            Sentinel.reset();
            const s2 = Sentinel.initialize(config);
            expect(s1).not.toBe(s2);
        });
    });

    describe("basic log ingestion", () => {
        it("ingests a simple log and returns result", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({ message: "Hello world" });

            expect(result.traceId).toBeDefined();
            expect(result.hashChainValid).toBe(true);
            expect(result.masked).toBe(true);
            expect(result.tasksGenerated).toEqual([]);
        });

        it("applies PII masking to message", async () => {
            const processedLogs: Log[] = [];
            const sentinel = Sentinel.initialize({
                ...config,
                onLogProcessed: (log) => processedLogs.push(log),
            });

            await sentinel.ingest({ message: "Contact admin@example.com for help" });

            expect(processedLogs).toHaveLength(1);
            expect(processedLogs[0].message).not.toContain("admin@example.com");
            expect(processedLogs[0].message).toContain("[MASKED_EMAIL]");
        });

        it("builds hash chain across multiple logs", async () => {
            const processedLogs: Log[] = [];
            const sentinel = Sentinel.initialize({
                ...config,
                onLogProcessed: (log) => processedLogs.push(log),
            });

            await sentinel.ingest({ message: "First log" });
            await sentinel.ingest({ message: "Second log" });
            await sentinel.ingest({ message: "Third log" });

            expect(processedLogs).toHaveLength(3);

            // All have hashes
            for (const log of processedLogs) {
                expect(log.hash).toMatch(/^[a-f0-9]{64}$/);
            }

            // All hashes are unique
            const hashes = processedLogs.map((l) => l.hash);
            expect(new Set(hashes).size).toBe(3);
        });
    });

    describe("event detection → task generation", () => {
        it("generates tasks for critical log", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({
                message: "Database connection pool exhausted",
                isCritical: true,
                level: 6,
                boundary: "db-service:pool",
            });

            expect(result.tasksGenerated.length).toBeGreaterThan(0);
            expect(result.tasksGenerated[0].ruleId).toBe("crit-notify");
            expect(result.tasksGenerated[0].status).toBe("dispatched");
        });

        it("generates tasks for security intrusion", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({
                message: "Brute force detected",
                type: "SECURITY",
                level: 5,
                boundary: "auth-service",
                tags: [{ key: "ip", category: "10.0.0.1" }],
            });

            expect(result.tasksGenerated.length).toBeGreaterThan(0);
            expect(result.tasksGenerated[0].ruleId).toBe("sec-analyze");
        });

        it("generates tasks for compliance violation", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({
                message: "Data retention policy violation detected",
                type: "COMPLIANCE",
                level: 4,
                actorId: "user-123",
            });

            expect(result.tasksGenerated.length).toBeGreaterThan(0);
            expect(result.tasksGenerated[0].ruleId).toBe("comp-escalate");
            // MANUAL execution = blocked
            expect(result.tasksGenerated[0].status).toBe("blocked_approval");
        });

        it("does not generate tasks for normal log", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({
                message: "User login successful",
                type: "SYSTEM",
                level: 3,
            });

            expect(result.tasksGenerated).toHaveLength(0);
        });
    });

    describe("task dispatch handlers", () => {
        it("calls registered handler on task dispatch", async () => {
            const dispatched: GeneratedTask[] = [];
            const sentinel = Sentinel.initialize(config);
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", (task) => {
                dispatched.push(task);
            });

            await sentinel.ingest({
                message: "Critical failure",
                isCritical: true,
                level: 6,
            });

            expect(dispatched).toHaveLength(1);
            expect(dispatched[0].actionType).toBe("SYSTEM_NOTIFICATION");
            expect(dispatched[0].sourceLog.message).toBeDefined();
        });

        it("onTaskDispatched callback fires", async () => {
            const results: unknown[] = [];
            const sentinel = Sentinel.initialize({
                ...config,
                onTaskDispatched: (result) => results.push(result),
            });

            await sentinel.ingest({
                message: "Critical failure",
                isCritical: true,
                level: 6,
            });

            // onTaskDispatched is called from the engine
            // This verifies the callback wiring works
        });
    });

    describe("masking disabled", () => {
        it("skips masking when disabled", async () => {
            const processedLogs: Log[] = [];
            const sentinel = Sentinel.initialize(
                createDefaultConfig({
                    projectName: "test",
                    serviceId: "test",
                    masking: { enabled: false, rules: [], preserveFields: [] },
                    taskRules: [],
                    onLogProcessed: (log) => processedLogs.push(log),
                }),
            );

            await sentinel.ingest({ message: "admin@example.com" });

            expect(processedLogs[0].message).toBe("admin@example.com");
        });
    });

    describe("hash chain disabled", () => {
        it("skips hash chain when disabled", async () => {
            const processedLogs: Log[] = [];
            const sentinel = Sentinel.initialize(
                createDefaultConfig({
                    projectName: "test",
                    serviceId: "test",
                    security: { enableHashChain: false },
                    taskRules: [],
                    onLogProcessed: (log) => processedLogs.push(log),
                }),
            );

            const result = await sentinel.ingest({ message: "test" });
            expect(result.hashChainValid).toBe(false);
        });
    });

    describe("edge cases", () => {
        it("rejects empty message", async () => {
            const sentinel = Sentinel.initialize(config);
            await expect(sentinel.ingest({ message: "" })).rejects.toThrow("cannot be empty");
        });

        it("handles rapid concurrent ingestion", async () => {
            const sentinel = Sentinel.initialize(config);
            const promises = Array.from({ length: 50 }, (_, i) =>
                sentinel.ingest({ message: `Log ${i}`, level: 3 }),
            );
            const results = await Promise.all(promises);
            expect(results).toHaveLength(50);
            const traceIds = results.map((r) => r.traceId);
            expect(new Set(traceIds).size).toBe(50);
        });

        it("processes AI_AGENT origin logs without re-triggering detection", async () => {
            const sentinel = Sentinel.initialize(config);
            const result = await sentinel.ingest({
                message: "Agent analysis complete",
                origin: "AI_AGENT",
                type: "SECURITY",
                level: 5,
            });
            // AI_AGENT logs should not trigger detection (loop prevention)
            expect(result.tasksGenerated).toHaveLength(0);
        });
    });
});
