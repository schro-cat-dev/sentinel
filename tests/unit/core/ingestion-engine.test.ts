/**
 * IngestionEngine Unit Tests
 *
 * P0: agentBackLog/traceInfo passthrough, callback wiring
 * P1: dual-mode log reuse, normalizeOnly masking
 * P2: performance, error handling
 */
import { describe, it, expect, vi } from "vitest";
import { IngestionEngine } from "../../../src/core/engine/ingestion-engine";
import { LogNormalizer } from "../../../src/core/engine/log-normalizer";
import { IntegritySigner } from "../../../src/security/integrity-signer";
import { EventDetector } from "../../../src/core/detection/event-detector";
import { TaskGenerator } from "../../../src/core/task/task-generator";
import { TaskExecutor } from "../../../src/core/task/task-executor";
import { createTestConfig, createTestTaskRule } from "../../helpers/fixtures";
import type { SentinelConfig } from "../../../src/configs/sentinel-config";
import type { GeneratedTask, TaskResult } from "../../../src/types/task";

function createEngine(configOverrides: Partial<SentinelConfig> = {}) {
    const config = createTestConfig({
        masking: { enabled: false, rules: [], preserveFields: [] },
        security: { enableHashChain: false },
        ...configOverrides,
    });
    return {
        engine: new IngestionEngine({
            config,
            normalizer: new LogNormalizer(config.serviceId),
            signer: new IntegritySigner(),
            detector: new EventDetector(),
            taskGenerator: new TaskGenerator(config.taskRules ?? []),
            taskExecutor: new TaskExecutor(),
        }),
        config,
    };
}

describe("IngestionEngine", () => {
    // ===== P0: BUG-01/02 — フィールドパススルー =====
    describe("field passthrough (P0)", () => {
        it("preserves agentBackLog through normalize", async () => {
            const { engine } = createEngine();
            const backLog = {
                agentId: "agent-1",
                taskId: "task-1",
                actionType: "analyze",
                model: "gpt-4",
                inputHash: "abc",
                isAsynchronous: false,
                generatedAt: new Date().toISOString(),
                processorInfo: {
                    resourceInfo: {
                        cpu: { quantity: 1, unit: "core" },
                        memory: { quantity: 4, unit: "GB" },
                        outerStorage: { quantity: 10, unit: "GB" },
                        serviceInfo: {
                            serviceId: "svc",
                            instanceId: "i-1",
                            version: "1.0",
                            deployment: "prod",
                        },
                    },
                },
                status: "success" as const,
            };

            const result = engine.normalizeOnly({
                message: "test with backlog",
                agentBackLog: backLog,
            });

            expect(result.agentBackLog).toBeDefined();
            expect(result.agentBackLog?.agentId).toBe("agent-1");
        });

        it("preserves traceInfo through normalize", async () => {
            const { engine } = createEngine();
            const result = engine.normalizeOnly({
                message: "test with traceInfo",
                traceInfo: "span-context-data",
            });

            expect(result.traceInfo).toBe("span-context-data");
        });

        it("handles undefined agentBackLog gracefully", async () => {
            const { engine } = createEngine();
            const result = engine.normalizeOnly({ message: "no backlog" });
            expect(result.agentBackLog).toBeUndefined();
        });
    });

    // ===== P0: BUG-03/04 — コールバック接続 =====
    describe("callback wiring (P0)", () => {
        it("invokes onTaskGenerated when task is generated", async () => {
            const onTaskGenerated = vi.fn();
            const { engine } = createEngine({
                security: { enableHashChain: false },
                taskRules: [
                    createTestTaskRule({
                        eventName: "SYSTEM_CRITICAL_FAILURE",
                        severity: "CRITICAL",
                    }),
                ],
                onTaskGenerated,
            });

            await engine.handle({ message: "critical failure", isCritical: true });

            expect(onTaskGenerated).toHaveBeenCalledTimes(1);
            const task = onTaskGenerated.mock.calls[0][0] as GeneratedTask;
            expect(task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        });

        it("invokes onTaskDispatched after dispatch", async () => {
            const onTaskDispatched = vi.fn();
            const { engine } = createEngine({
                security: { enableHashChain: false },
                taskRules: [
                    createTestTaskRule({
                        eventName: "SYSTEM_CRITICAL_FAILURE",
                        severity: "CRITICAL",
                    }),
                ],
                onTaskDispatched,
            });

            await engine.handle({ message: "critical failure", isCritical: true });

            expect(onTaskDispatched).toHaveBeenCalledTimes(1);
            const result = onTaskDispatched.mock.calls[0][0] as TaskResult;
            expect(result.status).toBe("dispatched");
        });

        it("invokes onLogProcessed after hash chain", async () => {
            const onLogProcessed = vi.fn();
            const { engine } = createEngine({
                security: { enableHashChain: true },
                onLogProcessed,
            });

            await engine.handle({ message: "test log" });

            expect(onLogProcessed).toHaveBeenCalledTimes(1);
            const log = onLogProcessed.mock.calls[0][0];
            expect(typeof log.hash).toBe("string");
            expect(log.hash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hex
        });

        it("does not crash when onTaskGenerated throws", async () => {
            const { engine } = createEngine({
                security: { enableHashChain: false },
                taskRules: [
                    createTestTaskRule({
                        eventName: "SYSTEM_CRITICAL_FAILURE",
                    }),
                ],
                onTaskGenerated: () => { throw new Error("boom"); },
            });

            const result = await engine.handle({ message: "critical", isCritical: true });
            expect(typeof result.traceId).toBe("string");
            expect(result.traceId.length).toBeGreaterThan(0);
        });
    });

    // ===== P1: normalizeOnly with masking =====
    describe("normalizeOnly with masking (P1)", () => {
        it("applies masking when enabled", () => {
            const { engine } = createEngine({
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                    preserveFields: ["traceId"],
                },
            });

            const result = engine.normalizeOnly({
                message: "contact alice@secret.com",
            });

            expect(result.message).not.toContain("alice@secret.com");
        });

        it("skips masking when disabled", () => {
            const { engine } = createEngine({
                masking: { enabled: false, rules: [], preserveFields: [] },
            });

            const result = engine.normalizeOnly({
                message: "contact alice@secret.com",
            });

            expect(result.message).toContain("alice@secret.com");
        });
    });

    // ===== P1: RES-02 — getLastProcessedLog =====
    describe("getLastProcessedLog (P1)", () => {
        it("stores last processed log after handle()", async () => {
            const { engine } = createEngine();

            expect(engine.getLastProcessedLog()).toBeNull();

            await engine.handle({ message: "first log" });
            const first = engine.getLastProcessedLog();
            expect(first).not.toBeNull();
            expect(first!.message).toBe("first log");

            await engine.handle({ message: "second log" });
            const second = engine.getLastProcessedLog();
            expect(second!.message).toBe("second log");
        });
    });

    // ===== P2: Concurrent hash chain =====
    describe("concurrent hash chain (P2)", () => {
        it("serializes concurrent calls via mutex", async () => {
            const { engine } = createEngine({
                security: { enableHashChain: true },
            });

            const results = await Promise.all(
                Array.from({ length: 10 }, (_, i) =>
                    engine.handle({ message: `log-${i}` })
                ),
            );

            expect(results.every((r) => r.hashChainValid)).toBe(true);
            const traceIds = results.map((r) => r.traceId);
            expect(new Set(traceIds).size).toBe(10);
        });
    });

    // ===== Error handling edge cases =====
    describe("error resilience", () => {
        it("callback exceptions do not break pipeline", async () => {
            let callCount = 0;
            const { engine } = createEngine({
                onLogProcessed: () => {
                    callCount++;
                    if (callCount === 1) throw new Error("callback error");
                },
            });

            await engine.handle({ message: "first" });
            await engine.handle({ message: "second" });

            expect(callCount).toBe(2);
        });

        it("ErrorRouter.route rejection inside emitSafe logs to console.error", async () => {
            // To cover lines 225-226, we need ErrorRouter.route() to reject.
            // route() has an internal try/catch, so we must make that catch block throw.
            // Strategy: mock console.error to throw on the specific call from route()'s catch,
            // which will cause the async route() promise to reject and hit the .catch() in emitSafe.

            // Step 1: create engine with errorRouting enabled and a throwing callback
            const { engine } = createEngine({
                errorRouting: {
                    enabled: true,
                    rules: [
                        {
                            match: {
                                severity: "WARNING",
                                kindPattern: {
                                    test: () => { throw new Error("regex exploded"); },
                                } as unknown as RegExp,
                            },
                            decisions: [],
                        },
                    ],
                },
                onLogProcessed: () => { throw new Error("callback boom"); },
            });

            // Step 2: intercept console.error — make first call (route's internal catch) throw
            let callIdx = 0;
            const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {
                callIdx++;
                if (callIdx === 1) {
                    // This is route()'s internal "routing failed" console.error
                    // Making it throw causes route() to reject
                    throw new Error("console.error blew up");
                }
                // Subsequent calls (emitSafe .catch, onError handler) succeed
            });

            await engine.handle({ message: "trigger error" });

            // Wait for the async .catch() on route() to fire
            await new Promise((resolve) => setTimeout(resolve, 100));

            const calls = stderrSpy.mock.calls.map((c) => c.map(String).join(" "));
            const hasRouterCatch = calls.some((msg) =>
                msg.includes("[Sentinel] ErrorRouter.route failed:"),
            );
            expect(hasRouterCatch).toBe(true);

            stderrSpy.mockRestore();
        });
    });
});
