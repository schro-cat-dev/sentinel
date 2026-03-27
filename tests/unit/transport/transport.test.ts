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
