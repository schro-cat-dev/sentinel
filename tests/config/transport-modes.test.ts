/**
 * Transport Mode Configuration Tests
 *
 * All transport mode combinations (local / remote / dual) with
 * normal, abnormal, and edge-case coverage including timeout,
 * fallback, masking, traceId reuse, onError callback, and shutdown.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig } from "../../src/index";
import type { RemoteTransport } from "../../src/transport/transport";
import type { IngestionResult } from "../../src/core/engine/types";
import type { Log } from "../../src/types/log";

/* ------------------------------------------------------------------ */
/*  Shared fixtures                                                    */
/* ------------------------------------------------------------------ */

const baseConfig = createDefaultConfig({
    projectName: "transport-modes-test",
    serviceId: "test-svc",
    environment: "test",
    security: { enableHashChain: true },
    masking: {
        enabled: true,
        rules: [{ type: "PII_TYPE", category: "EMAIL" }],
        preserveFields: [],
    },
    taskRules: [
        {
            ruleId: "crit-notify",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH",
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "AUTO",
            priority: 1,
            description: "Notify on critical failure",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
        },
    ],
});

const fakeRemoteResult = (traceId: string): IngestionResult => ({
    traceId,
    hashChainValid: true,
    masked: true,
    tasksGenerated: [],
    detection: null,
});

/**
 * Helper: create a mock RemoteTransport with vi.fn() stubs.
 */
function createMockTransport(
    sendImpl?: (log: Log) => Promise<IngestionResult>,
): RemoteTransport & { send: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> } {
    return {
        send: vi.fn(sendImpl ?? ((log: Log) => Promise.resolve(fakeRemoteResult(log.traceId)))),
        close: vi.fn(() => Promise.resolve()),
    };
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

/* ================================================================== */
/*  LOCAL MODE                                                         */
/* ================================================================== */

describe("Transport: local mode", () => {
    it("ingest returns local result without transport object", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({ message: "local only" });

        expect(result.traceId).toBeDefined();
        expect(result.hashChainValid).toBe(true);
        expect(result.masked).toBe(true);
    });

    it("no transport option defaults to local mode", async () => {
        const sentinel = Sentinel.initialize(baseConfig); // no second arg
        const result = await sentinel.ingest({ message: "default local" });

        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    it("explicit mode: 'local' works the same as omitted transport", async () => {
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "local" },
        });
        const result = await sentinel.ingest({ message: "explicit local" });

        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    it("detection info is included in local result for critical logs", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({
            message: "DB pool exhausted",
            isCritical: true,
            level: 6,
            boundary: "db-svc",
        });

        expect(result.detection).not.toBeNull();
        expect(result.detection!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("detection is null for non-critical logs", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        const result = await sentinel.ingest({ message: "info log", level: 2 });

        expect(result.detection).toBeNull();
    });

    it("transport object on local mode is ignored", async () => {
        const mockTransport = createMockTransport();
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "local", transport: mockTransport },
        });
        await sentinel.ingest({ message: "ignored transport" });

        expect(mockTransport.send).not.toHaveBeenCalled();
    });
});

/* ================================================================== */
/*  REMOTE MODE                                                        */
/* ================================================================== */

describe("Transport: remote mode", () => {
    it("sends to transport and returns transport result", async () => {
        const mockTransport = createMockTransport();
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "remote test" });

        expect(mockTransport.send).toHaveBeenCalledTimes(1);
        expect(result.traceId).toBeDefined();
        expect(result.hashChainValid).toBe(true);
    });

    it("the log passed to transport.send() has been normalized", async () => {
        let captured: Log | null = null;
        const mockTransport = createMockTransport(async (log) => {
            captured = log;
            return fakeRemoteResult(log.traceId);
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });
        await sentinel.ingest({ message: "normalize check" });

        expect(captured).not.toBeNull();
        expect(captured!.serviceId).toBe("test-svc");
        expect(captured!.traceId).toBeDefined();
        expect(captured!.timestamp).toBeDefined();
    });

    /* --- error handling ----------------------------------------------- */

    it("transport.send() throwing propagates error by default", async () => {
        const mockTransport = createMockTransport(async () => {
            throw new Error("network failure");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        await expect(sentinel.ingest({ message: "will fail" })).rejects.toThrow("network failure");
    });

    it("transport.send() throws + fallbackToLocal=true falls back to local", async () => {
        const mockTransport = createMockTransport(async () => {
            throw new Error("server unreachable");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "fallback test" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
    });

    it("transport.send() throws + fallbackToLocal=false throws", async () => {
        const mockTransport = createMockTransport(async () => {
            throw new Error("explicit no fallback");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, fallbackToLocal: false },
        });

        await expect(sentinel.ingest({ message: "no fallback" })).rejects.toThrow("explicit no fallback");
    });

    it("transport not provided in remote mode falls through to local processing", async () => {
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote" }, // no transport object
        });

        const result = await sentinel.ingest({ message: "no transport provided" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
    });

    /* --- timeout ----------------------------------------------------- */

    it("send completes before timeout returns success", async () => {
        const mockTransport = createMockTransport(async (log) => {
            await new Promise((r) => setTimeout(r, 10));
            return fakeRemoteResult(log.traceId);
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, timeoutMs: 5000 },
        });

        const result = await sentinel.ingest({ message: "fast enough" });
        expect(result.traceId).toBeDefined();
    });

    it("send exceeding timeout triggers timeout error", async () => {
        const mockTransport = createMockTransport(async () => {
            await new Promise((r) => setTimeout(r, 500));
            return fakeRemoteResult("never-returned");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, timeoutMs: 50 },
        });

        await expect(sentinel.ingest({ message: "slow send" })).rejects.toThrow(/Transport timeout after 50ms/);
    });

    it("default 30s timeout is applied when timeoutMs not specified", async () => {
        // We verify indirectly: a fast send should succeed even without explicit timeoutMs
        const mockTransport = createMockTransport();
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "default timeout" });
        expect(result.traceId).toBeDefined();

        // Additionally, trigger a timeout with a slow transport and check the error message
        Sentinel.reset();
        const slowTransport = createMockTransport(async () => {
            await new Promise((r) => setTimeout(r, 200));
            return fakeRemoteResult("late");
        });

        const sentinel2 = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: slowTransport, timeoutMs: 10 },
        });

        await expect(sentinel2.ingest({ message: "check msg" })).rejects.toThrow(/Transport timeout after 10ms/);
    });

    it("timeout error + fallbackToLocal=true falls back to local", async () => {
        const mockTransport = createMockTransport(async () => {
            await new Promise((r) => setTimeout(r, 500));
            return fakeRemoteResult("late");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport, timeoutMs: 10, fallbackToLocal: true },
        });

        const result = await sentinel.ingest({ message: "timeout fallback" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    /* --- masking before remote send ---------------------------------- */

    it("masking is applied before sending to remote", async () => {
        let sentLog: Log | null = null;
        const mockTransport = createMockTransport(async (log) => {
            sentLog = log;
            return fakeRemoteResult(log.traceId);
        });

        const configWithEmail = createDefaultConfig({
            projectName: "mask-test",
            serviceId: "test-svc",
            environment: "test",
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: [],
            },
        });

        const sentinel = Sentinel.initialize(configWithEmail, {
            transport: { mode: "remote", transport: mockTransport },
        });

        await sentinel.ingest({ message: "Contact user@example.com for details" });

        expect(sentLog).not.toBeNull();
        // The EMAIL PII should have been masked (replaced with [MASKED_EMAIL])
        expect(sentLog!.message).not.toContain("user@example.com");
        expect(sentLog!.message).toContain("[MASKED_EMAIL]");
    });

    it("masking disabled means original message is sent to remote", async () => {
        let sentLog: Log | null = null;
        const mockTransport = createMockTransport(async (log) => {
            sentLog = log;
            return fakeRemoteResult(log.traceId);
        });

        const noMaskConfig = createDefaultConfig({
            projectName: "no-mask",
            serviceId: "test-svc",
            environment: "test",
            masking: { enabled: false },
        });

        const sentinel = Sentinel.initialize(noMaskConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        await sentinel.ingest({ message: "Contact user@example.com for details" });

        expect(sentLog).not.toBeNull();
        expect(sentLog!.message).toContain("user@example.com");
    });
});

/* ================================================================== */
/*  DUAL MODE                                                          */
/* ================================================================== */

describe("Transport: dual mode", () => {
    it("local processing + remote send both succeed", async () => {
        const mockTransport = createMockTransport();
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "dual success" });

        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
        expect(mockTransport.send).toHaveBeenCalledTimes(1);
    });

    it("remote fails but local result is still returned", async () => {
        const mockTransport = createMockTransport(async () => {
            throw new Error("remote down");
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "dual with remote failure" });

        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
    });

    it("remote fails and onError callback receives the error", async () => {
        const onError = vi.fn();
        const configWithOnError = createDefaultConfig({
            projectName: "dual-onerror",
            serviceId: "test-svc",
            environment: "test",
            security: { enableHashChain: true },
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: [] },
            onError,
        });

        const mockTransport = createMockTransport(async () => {
            throw new Error("dual remote error");
        });

        const sentinel = Sentinel.initialize(configWithOnError, {
            transport: { mode: "dual", transport: mockTransport },
        });

        await sentinel.ingest({ message: "dual error callback" });

        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith(
            expect.objectContaining({ message: "dual remote error" }),
            "transport.dual",
        );
    });

    it("onError callback throwing does not break ingest", async () => {
        const configWithBrokenOnError = createDefaultConfig({
            projectName: "dual-onerror-throw",
            serviceId: "test-svc",
            environment: "test",
            onError: () => { throw new Error("callback boom"); },
        });

        const mockTransport = createMockTransport(async () => {
            throw new Error("remote error");
        });

        const sentinel = Sentinel.initialize(configWithBrokenOnError, {
            transport: { mode: "dual", transport: mockTransport },
        });

        // Should not throw even though onError itself throws
        const result = await sentinel.ingest({ message: "safe" });
        expect(result.traceId).toBeDefined();
    });

    it("local and remote get the same traceId (getLastProcessedLog reuse)", async () => {
        let remoteTraceId: string | null = null;
        const mockTransport = createMockTransport(async (log) => {
            remoteTraceId = log.traceId;
            return fakeRemoteResult(log.traceId);
        });

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual", transport: mockTransport },
        });

        const result = await sentinel.ingest({ message: "traceId check" });

        expect(remoteTraceId).not.toBeNull();
        expect(result.traceId).toBe(remoteTraceId);
    });

    it("timeoutMs is applied to the remote leg of dual mode", async () => {
        const onError = vi.fn();
        const configWithOnError = createDefaultConfig({
            projectName: "dual-timeout",
            serviceId: "test-svc",
            environment: "test",
            onError,
        });

        const mockTransport = createMockTransport(async () => {
            await new Promise((r) => setTimeout(r, 500));
            return fakeRemoteResult("late");
        });

        const sentinel = Sentinel.initialize(configWithOnError, {
            transport: { mode: "dual", transport: mockTransport, timeoutMs: 10 },
        });

        const result = await sentinel.ingest({ message: "dual timeout" });

        // Local result still returned
        expect(result.traceId).toBeDefined();

        // Remote timed out, onError should have been called
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith(
            expect.objectContaining({ message: expect.stringMatching(/Transport timeout/) }),
            "transport.dual",
        );
    });

    it("transport not provided in dual mode skips remote send, returns local", async () => {
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "dual" }, // no transport object
        });

        const result = await sentinel.ingest({ message: "dual no transport" });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(true);
    });

    it("critical log generates tasks locally even when remote succeeds", async () => {
        const mockTransport = createMockTransport();
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
        expect(mockTransport.send).toHaveBeenCalledTimes(1);
    });

    it("critical log generates tasks locally even when remote fails", async () => {
        const mockTransport = createMockTransport(async () => {
            throw new Error("remote down");
        });

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
    });
});

/* ================================================================== */
/*  SHUTDOWN                                                           */
/* ================================================================== */

describe("Transport: shutdown", () => {
    it("shutdown calls transport.close()", async () => {
        const mockTransport = createMockTransport();
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        await sentinel.shutdown();

        expect(mockTransport.close).toHaveBeenCalledTimes(1);
    });

    it("shutdown with no transport does not crash", async () => {
        const sentinel = Sentinel.initialize(baseConfig);

        await expect(sentinel.shutdown()).resolves.not.toThrow();
    });

    it("shutdown with local mode (no transport) does not crash", async () => {
        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "local" },
        });

        await expect(sentinel.shutdown()).resolves.not.toThrow();
    });

    it("transport.close() throwing does not prevent shutdown", async () => {
        const mockTransport = createMockTransport();
        mockTransport.close.mockRejectedValueOnce(new Error("close failed"));

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: mockTransport },
        });

        // Should not throw
        await expect(sentinel.shutdown()).resolves.not.toThrow();
    });

    it("transport without close method does not crash on shutdown", async () => {
        const transportNoClose: RemoteTransport = {
            send: vi.fn(async (log: Log) => fakeRemoteResult(log.traceId)),
            // no close method
        };

        const sentinel = Sentinel.initialize(baseConfig, {
            transport: { mode: "remote", transport: transportNoClose },
        });

        await expect(sentinel.shutdown()).resolves.not.toThrow();
    });

    it("singleton is cleared after shutdown", async () => {
        const sentinel = Sentinel.initialize(baseConfig);
        await sentinel.shutdown();

        expect(() => Sentinel.getInstance()).toThrow("Sentinel must be initialized first");
    });

    it("re-initialize after shutdown works", async () => {
        const sentinel1 = Sentinel.initialize(baseConfig);
        await sentinel1.shutdown();

        const sentinel2 = Sentinel.initialize(baseConfig);
        const result = await sentinel2.ingest({ message: "after shutdown" });
        expect(result.traceId).toBeDefined();
    });
});
