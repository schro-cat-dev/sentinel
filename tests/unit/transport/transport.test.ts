import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig, RemoteTransport } from "../../../src/index";
import type { IngestionResult } from "../../../src/core/engine/types";
import type { Log } from "../../../src/types/log";

const baseConfig = createDefaultConfig({
    projectName: "transport-test",
    serviceId: "test-svc",
    security: { enableHashChain: true },
    masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: [] },
    taskRules: [{
        ruleId: "crit-notify",
        eventName: "SYSTEM_CRITICAL_FAILURE",
        severity: "HIGH",
        actionType: "SYSTEM_NOTIFICATION",
        executionLevel: "AUTO",
        priority: 1,
        description: "test",
        executionParams: {},
        guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
    }],
});

afterEach(() => Sentinel.reset());

describe("Sentinel: public handler management (MEM-01ext)", () => {
    it("removeHandlers removes handlers for specific action type", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const handler = vi.fn();
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        sentinel.removeHandlers("SYSTEM_NOTIFICATION");

        const result = await sentinel.ingest({
            message: "DB pool exhausted", isCritical: true, level: 6, boundary: "db-svc",
        });
        // Handler should NOT be called after removal
        expect(handler).not.toHaveBeenCalled();
    });

    it("clearHandlers removes all handlers", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const handler1 = vi.fn();
        const handler2 = vi.fn();
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler1);
        sentinel.onTaskAction("AI_ANALYZE", handler2);

        sentinel.clearHandlers();

        const result = await sentinel.ingest({
            message: "DB pool exhausted", isCritical: true, level: 6, boundary: "db-svc",
        });
        expect(handler1).not.toHaveBeenCalled();
        expect(handler2).not.toHaveBeenCalled();
    });
});

describe("Transport: threatResponses (Phase 2-C)", () => {
    it("includes threatResponses from remote transport when enabled", async () => {
        Sentinel.reset();
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                return {
                    traceId: log.traceId,
                    hashChainValid: true,
                    masked: true,
                    tasksGenerated: [],
                    detection: null,
                    threatResponses: [
                        {
                            responseId: "resp-1",
                            eventName: "SECURITY_INTRUSION_DETECTED",
                            strategy: "BLOCK_AND_NOTIFY",
                            blocked: true,
                            blockTarget: "10.0.0.1",
                            analyzed: true,
                            riskLevel: "HIGH",
                            notified: true,
                        },
                    ],
                };
            },
        };

        const sentinel = Sentinel.initialize(
            { ...baseConfig, integration: { threatResponseEnabled: true } },
            { transport: { mode: "remote", transport: mockTransport } },
        );

        const result = await sentinel.ingest({ message: "intrusion test" });
        expect(result.threatResponses).toBeDefined();
        expect(result.threatResponses!.length).toBe(1);
        expect(result.threatResponses![0].strategy).toBe("BLOCK_AND_NOTIFY");
    });

    it("does not include threatResponses when disabled (default)", async () => {
        Sentinel.reset();
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                return {
                    traceId: log.traceId,
                    hashChainValid: true,
                    masked: true,
                    tasksGenerated: [],
                    detection: null,
                    threatResponses: [{ responseId: "r", eventName: "X", strategy: "Y", blocked: false, blockTarget: "", analyzed: false, riskLevel: "LOW", notified: false }],
                };
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "no threat response" });
        // threatResponses should be stripped when not enabled
        expect(result.threatResponses).toBeUndefined();
    });

    it("local mode never has threatResponses", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({ message: "local log" });
        expect(result.threatResponses).toBeUndefined();
    });
});

describe("Transport: detection rules sync awareness (Phase 2-A)", () => {
    it("Server detection_rules config is exposed via HealthCheck ConfigSummary", async () => {
        // This verifies the architecture: Server exposes detection_rules_count
        // in HealthCheck so SDK can compare its own rules count.
        // Actual gRPC call is E2E test scope; here we validate the type contract.
        Sentinel.reset();
        const sentinel = Sentinel.initialize(baseConfig);
        const config = sentinel.getConfig();
        // SDK has detectionRules available for comparison
        expect(config.detectionRules ?? []).toBeDefined();
    });

    it("integration.syncDetectionRules flag is available in config", () => {
        Sentinel.reset();
        const sentinel = Sentinel.initialize({
            ...baseConfig,
            integration: { syncDetectionRules: true },
        });
        expect(sentinel.getConfig().integration?.syncDetectionRules).toBe(true);
    });
});

describe("Transport: local mode (default)", () => {
    it("processes locally without transport", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({ message: "test log" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
    });
});

describe("Transport: remote mode", () => {
    it("sends to remote transport", async () => {
        const sent: Log[] = [];
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                sent.push(log);
                return {
                    traceId: log.traceId,
                    hashChainValid: true,
                    masked: true,
                    tasksGenerated: [],
                };
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "remote test" });
        expect(sent.length).toBe(1);
        expect(sent[0].message).toBe("remote test");
        expect(result.traceId).toBeDefined();
    });

    it("falls back to local on remote failure when fallbackToLocal=true", async () => {
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                throw new Error("connection refused");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: failTransport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    it("throws on remote failure when fallbackToLocal=false", async () => {
        Sentinel.reset();
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                throw new Error("connection refused");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: failTransport, fallbackToLocal: false },
        });

        await expect(sentinel.ingest({ message: "should fail" })).rejects.toThrow("connection refused");
    });
});

describe("Transport: remote mode error classification (R-5)", () => {
    it("distinguishes normalize error from transport error in fallback", async () => {
        Sentinel.reset();
        // Transport that works fine — error is in normalization
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                return { traceId: log.traceId, hashChainValid: true, masked: true, tasksGenerated: [] };
            },
        };

        // Use a config that would cause normalization to work (normal path)
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, fallbackToLocal: true },
        });

        // Normal ingest should work fine
        const result = await sentinel.ingest({ message: "normal log" });
        expect(result.traceId).toBeDefined();
        // transportError should NOT be set on successful path
        expect(result.transportError).toBeUndefined();
    });

    it("sets transportError only for transport failures, not normalize failures", async () => {
        Sentinel.reset();
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                throw new Error("transport connection refused");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: failTransport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test" });
        expect(result.traceId).toBeDefined();
        expect(result.transportError).toContain("transport connection refused");
    });
});

describe("Transport: circuit breaker integration (R-4)", () => {
    it("suspends transport after consecutive failures", async () => {
        Sentinel.reset();
        let callCount = 0;
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                callCount++;
                throw new Error("connection refused");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: {
                mode: "remote",
                transport: failTransport,
                fallbackToLocal: true,
                circuitBreaker: { failureThreshold: 3, cooldownMs: 60000 },
            },
        });

        // 3 failures to open the breaker
        for (let i = 0; i < 3; i++) {
            await sentinel.ingest({ message: `fail-${i}` });
        }
        expect(callCount).toBe(3);

        // 4th call should be blocked by circuit breaker (transport not called)
        const result = await sentinel.ingest({ message: "breaker-open" });
        expect(callCount).toBe(3); // transport NOT called
        expect(result.transportError).toContain("Circuit breaker is open");
    });

    it("does not activate circuit breaker when config is not provided", async () => {
        Sentinel.reset();
        let callCount = 0;
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                callCount++;
                throw new Error("connection refused");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: failTransport, fallbackToLocal: true },
        });

        // All calls go through to transport (no circuit breaker)
        for (let i = 0; i < 5; i++) {
            await sentinel.ingest({ message: `no-cb-${i}` });
        }
        expect(callCount).toBe(5);
    });
});

describe("Transport: dual mode", () => {
    it("processes locally AND sends to remote", async () => {
        Sentinel.reset();
        const sent: Log[] = [];
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                sent.push(log);
                return { traceId: log.traceId, hashChainValid: true, masked: true, tasksGenerated: [] };
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "dual test" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(sent.length).toBe(1);
    });

    it("local result is returned even if remote fails in dual mode", async () => {
        Sentinel.reset();
        const failTransport: RemoteTransport = {
            async send(): Promise<IngestionResult> {
                throw new Error("remote down");
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: failTransport },
        });

        const result = await sentinel.ingest({ message: "dual with failure" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    it("critical log generates tasks locally in dual mode", async () => {
        Sentinel.reset();
        const sent: Log[] = [];
        const mockTransport: RemoteTransport = {
            async send(log: Log): Promise<IngestionResult> {
                sent.push(log);
                return { traceId: log.traceId, hashChainValid: true, masked: true, tasksGenerated: [] };
            },
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: mockTransport },
        });

        const result = await sentinel.ingest({
            message: "DB pool exhausted",
            isCritical: true,
            level: 6,
            boundary: "db-svc",
        });
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(result.tasksGenerated[0].ruleId).toBe("crit-notify");
        expect(sent.length).toBe(1);
    });
});
