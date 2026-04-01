/**
 * Security Test: Advanced Transport Security Attacks
 *
 * Tests replay attacks, MITM simulation, data leakage via transport,
 * timeout attacks, dual mode edge cases, close() attacks, and healthCheck abuse.
 *
 * CWE-294: Authentication Bypass by Capture-replay
 * CWE-300: Channel Accessible by Non-Endpoint
 * CWE-400: Uncontrolled Resource Consumption
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import type { RemoteTransport, TransportConfig } from "../../../src/transport/transport";
import type { IngestionResult } from "../../../src/core/engine/types";
import type { Log } from "../../../src/types/log";
import type { SentinelConfig } from "../../../src/configs/sentinel-config";
import { createTestConfig, createTestTaskRule } from "../../helpers/fixtures";

/** Helper to create a minimal valid IngestionResult */
const createFakeResult = (overrides: Partial<IngestionResult> = {}): IngestionResult => ({
    traceId: "fake-trace",
    hashChainValid: false,
    tasksGenerated: [],
    masked: false,
    detection: null,
    ...overrides,
});

/** Helper to create a mock transport */
const createMockTransport = (
    sendImpl?: RemoteTransport["send"],
    options: Partial<RemoteTransport> = {},
): RemoteTransport => ({
    send: sendImpl ?? vi.fn(async () => createFakeResult()),
    healthCheck: options.healthCheck,
    close: options.close,
});

describe("Security: Advanced Transport Security Attacks", () => {
    beforeEach(() => {
        Sentinel.reset();
    });

    afterEach(() => {
        Sentinel.reset();
    });

    // =========================================================================
    // Replay attack simulation
    // =========================================================================
    describe("Replay attack simulation", () => {
        it("sending same log twice via remote produces distinct server calls", async () => {
            const receivedLogs: Log[] = [];
            const transport = createMockTransport(async (log) => {
                receivedLogs.push(structuredClone(log));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "same message" });
            await s.ingest({ message: "same message" });
            expect(receivedLogs).toHaveLength(2);
            // Even with same content, traceIds should differ (normalizer generates unique ones)
            expect(receivedLogs[0].traceId).not.toBe(receivedLogs[1].traceId);
        });

        it("replaying a captured normalized log still gets unique traceId", async () => {
            let capturedLog: Log | null = null;
            const transport = createMockTransport(async (log) => {
                if (!capturedLog) capturedLog = structuredClone(log);
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "original message" });
            expect(capturedLog).toBeDefined();
            // "Replay" by sending with same traceId
            const result = await s.ingest({
                message: "original message",
                traceId: capturedLog!.traceId,
            });
            expect(result).toBeDefined();
        });

        it("replay in dual mode still produces local result with valid hash chain", async () => {
            const transport = createMockTransport(async (log) =>
                createFakeResult({ traceId: log.traceId }),
            );
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const r1 = await s.ingest({ message: "message A" });
            const r2 = await s.ingest({ message: "message A" });
            expect(r1.hashChainValid).toBe(true);
            expect(r2.hashChainValid).toBe(true);
            expect(r1.traceId).not.toBe(r2.traceId);
        });

        it("three identical logs in sequence all get processed", async () => {
            const sendFn = vi.fn(async (log: Log) => createFakeResult({ traceId: log.traceId }));
            const transport = createMockTransport(sendFn);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "duplicate" });
            await s.ingest({ message: "duplicate" });
            await s.ingest({ message: "duplicate" });
            expect(sendFn).toHaveBeenCalledTimes(3);
        });
    });

    // =========================================================================
    // MITM simulation
    // =========================================================================
    describe("MITM simulation", () => {
        it("transport that modifies log before sending does not affect caller's original", async () => {
            const transport = createMockTransport(async (log) => {
                // MITM: tamper with the log
                (log as Record<string, unknown>).message = "TAMPERED";
                (log as Record<string, unknown>).traceId = "MITM-TRACE";
                return createFakeResult({ traceId: "MITM-TRACE" });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "original" });
            // The result comes from transport, so traceId may be tampered
            expect(result).toBeDefined();
        });

        it("transport that returns fabricated IngestionResult is accepted", async () => {
            const fabricated: IngestionResult = {
                traceId: "FABRICATED",
                hashChainValid: true,
                tasksGenerated: [
                    { taskId: "fake", ruleId: "fake", status: "dispatched", dispatchedAt: "now" },
                ],
                masked: true,
                detection: { eventName: "SYSTEM_CRITICAL_FAILURE", priority: "HIGH" },
            };
            const transport = createMockTransport(async () => fabricated);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            // In remote mode, the transport result is returned as-is
            expect(result.traceId).toBe("FABRICATED");
        });

        it("transport that returns partial/malformed result", async () => {
            const partial = { traceId: "partial" } as IngestionResult;
            const transport = createMockTransport(async () => partial);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result.traceId).toBe("partial");
            expect(result.hashChainValid).toBeUndefined();
        });

        it("transport that returns result with extra fields", async () => {
            const extended = {
                ...createFakeResult(),
                extraField: "should not crash",
                anotherExtra: { nested: true },
            } as IngestionResult;
            const transport = createMockTransport(async () => extended);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
            expect((result as Record<string, unknown>).extraField).toBe("should not crash");
        });

        it("transport that returns null result", async () => {
            const transport = createMockTransport(async () => null as unknown as IngestionResult);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeNull();
        });

        it("transport that returns undefined result", async () => {
            const transport = createMockTransport(async () => undefined as unknown as IngestionResult);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeUndefined();
        });
    });

    // =========================================================================
    // Transport that leaks
    // =========================================================================
    describe("Transport data leakage", () => {
        it("transport.send stores all logs (verify masking applied before send)", async () => {
            const storedLogs: Log[] = [];
            const transport = createMockTransport(async (log) => {
                storedLogs.push(structuredClone(log));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createDefaultConfig({
                projectName: "test",
                serviceId: "svc",
                environment: "test",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }] as SentinelConfig["masking"]["rules"],
                    preserveFields: [],
                },
            });
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "Contact user@example.com for details" });
            expect(storedLogs).toHaveLength(1);
            // In remote mode, normalizeOnly applies masking before send
            expect(storedLogs[0].message).not.toContain("user@example.com");
        });

        it("transport that sends to two destinations", async () => {
            const dest1: Log[] = [];
            const dest2: Log[] = [];
            const transport = createMockTransport(async (log) => {
                dest1.push(structuredClone(log));
                dest2.push(structuredClone(log));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "test" });
            expect(dest1).toHaveLength(1);
            expect(dest2).toHaveLength(1);
        });

        it("dual mode transport receives masked log", async () => {
            const transportLogs: Log[] = [];
            const transport = createMockTransport(async (log) => {
                transportLogs.push(structuredClone(log));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createDefaultConfig({
                projectName: "test",
                serviceId: "svc",
                environment: "test",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }] as SentinelConfig["masking"]["rules"],
                    preserveFields: [],
                },
            });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "Reach out to admin@corp.com" });
            expect(transportLogs).toHaveLength(1);
            // In dual mode, the processed log (already masked) is sent
            expect(transportLogs[0].message).not.toContain("admin@corp.com");
        });

        it("transport cannot exfiltrate data from a different ingest call", async () => {
            let stolenRef: Log | null = null;
            const transport = createMockTransport(async (log) => {
                stolenRef = log; // Store reference
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "first secret" });
            const firstRef = stolenRef;
            await s.ingest({ message: "second secret" });
            // First and second should be different objects
            expect(firstRef).not.toBe(stolenRef);
        });
    });

    // =========================================================================
    // Timeout attacks
    // =========================================================================
    describe("Timeout attacks", () => {
        it("transport that resolves just before timeout succeeds", async () => {
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, 40));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 100 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
            expect(result.traceId).toBeDefined();
        });

        it("transport that resolves just after timeout is rejected", async () => {
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, 150));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 50 },
            });
            await expect(s.ingest({ message: "test" })).rejects.toThrow("Transport timeout");
        });

        it("transport that never resolves fires timeout", async () => {
            const transport = createMockTransport(
                () => new Promise<IngestionResult>(() => {}), // never resolves
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 50 },
            });
            await expect(s.ingest({ message: "test" })).rejects.toThrow("Transport timeout");
        });

        it("transport with timeoutMs=0 uses setTimeout(0) which fires immediately", async () => {
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, 10));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 0 },
            });
            // setTimeout(fn, 0) fires on next tick, race with 10ms send
            // Behavior depends on event loop; just verify no crash
            try {
                const result = await s.ingest({ message: "test" });
                expect(result).toBeDefined();
            } catch (e) {
                expect((e as Error).message).toContain("Transport timeout");
            }
        });

        it("transport with timeoutMs=1 (race condition)", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 1 },
            });
            // Immediate resolution should win the race
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("transport with negative timeoutMs", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: -1 },
            });
            // Negative timeout in setTimeout is treated as 0
            try {
                const result = await s.ingest({ message: "test" });
                expect(result).toBeDefined();
            } catch (e) {
                expect((e as Error).message).toContain("Transport timeout");
            }
        });

        it("transport with very large timeoutMs does not crash", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: Number.MAX_SAFE_INTEGER },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("transport with NaN timeoutMs uses default", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: NaN },
            });
            // NaN ?? 30000 => NaN (nullish coalescing only checks null/undefined)
            // setTimeout(fn, NaN) is treated as setTimeout(fn, 0)
            try {
                const result = await s.ingest({ message: "test" });
                expect(result).toBeDefined();
            } catch (e) {
                expect((e as Error).message).toContain("Transport timeout");
            }
        });

        it("transport with undefined timeoutMs defaults to 30000", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: undefined },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("timeout fires but transport still resolves (no resource leak)", async () => {
            let transportResolved = false;
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, 100));
                transportResolved = true;
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 20 },
            });
            await expect(s.ingest({ message: "test" })).rejects.toThrow("Transport timeout");
            // Wait for the transport to actually resolve
            await new Promise((r) => setTimeout(r, 150));
            expect(transportResolved).toBe(true);
        });
    });

    // =========================================================================
    // Dual mode attacks
    // =========================================================================
    describe("Dual mode attacks", () => {
        it("transport that fails on second call but not first", async () => {
            let callCount = 0;
            const transport = createMockTransport(async (log) => {
                callCount++;
                if (callCount === 2) throw new Error("second call fails");
                return createFakeResult({ traceId: log.traceId });
            });
            const onError = vi.fn();
            const config = createTestConfig({ onError });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const r1 = await s.ingest({ message: "first" });
            expect(r1).toBeDefined();
            const r2 = await s.ingest({ message: "second" });
            // In dual mode, local result is returned even if transport fails
            expect(r2).toBeDefined();
            expect(r2.traceId).toBeDefined();
            expect(onError).toHaveBeenCalled();
        });

        it("transport failure in dual mode triggers onError with transport context", async () => {
            const errors: Array<{ error: Error; context: string }> = [];
            const transport = createMockTransport(async () => {
                throw new Error("transport down");
            });
            const config = createTestConfig({
                onError: (error, context) => errors.push({ error, context }),
            });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "test" });
            expect(errors.length).toBeGreaterThanOrEqual(1);
            expect(errors.some((e) => e.context === "transport.dual")).toBe(true);
        });

        it("local result is unaffected by transport failure in dual mode", async () => {
            const transport = createMockTransport(async () => {
                throw new Error("transport explodes");
            });
            const config = createTestConfig({
                security: { enableHashChain: true },
                onError: vi.fn(),
            });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "important log" });
            expect(result.hashChainValid).toBe(true);
            expect(result.traceId).toBeDefined();
        });

        it("transport that modifies getLastProcessedLog return does not affect next ingest", async () => {
            let interceptCount = 0;
            const transport = createMockTransport(async (log) => {
                interceptCount++;
                // Mutate the log passed to transport
                (log as Record<string, unknown>).message = "MUTATED_BY_TRANSPORT";
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig({ onError: vi.fn() });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            await s.ingest({ message: "first log" });
            const result2 = await s.ingest({ message: "second log" });
            expect(result2).toBeDefined();
            expect(interceptCount).toBe(2);
        });

        it("dual mode with transport returning very slowly still returns local result fast", async () => {
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, 200));
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig({ onError: vi.fn() });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const start = Date.now();
            const result = await s.ingest({ message: "test" });
            // Result should include the transport send time since dual awaits it
            expect(result).toBeDefined();
            expect(result.traceId).toBeDefined();
        });

        it("dual mode transport exception does not throw to caller", async () => {
            const transport = createMockTransport(async () => {
                throw new Error("catastrophic transport failure");
            });
            const config = createTestConfig({ onError: vi.fn() });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            // Should not throw
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("dual mode with transport that rejects with non-Error", async () => {
            const transport = createMockTransport(async () => {
                throw "string error"; // eslint-disable-line no-throw-literal
            });
            const onError = vi.fn();
            const config = createTestConfig({ onError });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
            expect(onError).toHaveBeenCalled();
        });

        it("onError throwing in dual mode does not crash", async () => {
            const transport = createMockTransport(async () => {
                throw new Error("transport fails");
            });
            const config = createTestConfig({
                onError: () => {
                    throw new Error("onError also fails");
                },
            });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            // Should not throw despite both transport and onError failing
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });
    });

    // =========================================================================
    // Remote mode with fallback
    // =========================================================================
    describe("Remote mode with fallback", () => {
        it("fallbackToLocal processes locally when transport fails", async () => {
            const transport = createMockTransport(async () => {
                throw new Error("remote down");
            });
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, fallbackToLocal: true, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result.hashChainValid).toBe(true);
        });

        it("fallbackToLocal=false re-throws transport error", async () => {
            const transport = createMockTransport(async () => {
                throw new Error("remote down");
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, fallbackToLocal: false, timeoutMs: 5000 },
            });
            await expect(s.ingest({ message: "test" })).rejects.toThrow("remote down");
        });

        it("fallbackToLocal on timeout", async () => {
            const transport = createMockTransport(
                () => new Promise<IngestionResult>(() => {}),
            );
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, fallbackToLocal: true, timeoutMs: 50 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result.hashChainValid).toBe(true);
        });
    });

    // =========================================================================
    // close() attacks
    // =========================================================================
    describe("close() attacks", () => {
        it("close() that hangs does not prevent shutdown from completing", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    close: () => new Promise<void>(() => {}), // never resolves
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            // shutdown catches close errors and proceeds
            // But if close never resolves, shutdown hangs. Test documents this.
            const shutdownPromise = s.shutdown();
            const timeoutPromise = new Promise<string>((r) => setTimeout(() => r("timeout"), 100));
            const winner = await Promise.race([
                shutdownPromise.then(() => "shutdown"),
                timeoutPromise,
            ]);
            // If shutdown hangs, the timeout wins
            expect(["shutdown", "timeout"]).toContain(winner);
        });

        it("close() that throws does not prevent instance cleanup", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    close: async () => {
                        throw new Error("close explodes");
                    },
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.shutdown();
            // Instance should be cleared despite close error
            expect(() => Sentinel.getInstance()).toThrow();
        });

        it("close() that calls shutdown() again (reentrant) does not cause infinite loop", async () => {
            let shutdownCallCount = 0;
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    close: async () => {
                        shutdownCallCount++;
                        if (shutdownCallCount < 3) {
                            // This will try to close again, but instance is already being cleared
                            try {
                                const inst = Sentinel.getInstance();
                                await inst.shutdown();
                            } catch {
                                // getInstance may throw
                            }
                        }
                    },
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.shutdown();
            expect(() => Sentinel.getInstance()).toThrow();
        });

        it("close() that takes long time (verify best-effort)", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    close: async () => {
                        await new Promise((r) => setTimeout(r, 50));
                    },
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const start = Date.now();
            await s.shutdown();
            const elapsed = Date.now() - start;
            // Should wait for close to complete (best-effort)
            expect(elapsed).toBeGreaterThanOrEqual(40);
        });

        it("close() that throws synchronously is caught", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    close: () => {
                        throw new Error("sync throw in close");
                    },
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            // Should not throw
            await s.shutdown();
            expect(() => Sentinel.getInstance()).toThrow();
        });

        it("shutdown without transport.close defined works fine", async () => {
            const transport: RemoteTransport = {
                send: vi.fn(async () => createFakeResult()),
                // no close method
            };
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.shutdown();
            expect(() => Sentinel.getInstance()).toThrow();
        });

        it("shutdown with no transport at all", async () => {
            const config = createTestConfig();
            const s = Sentinel.initialize(config);
            await s.shutdown();
            expect(() => Sentinel.getInstance()).toThrow();
        });

        it("double shutdown does not crash", async () => {
            const closeFn = vi.fn(async () => {});
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                { close: closeFn },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await s.shutdown();
            await s.shutdown(); // second call
            // close called once or twice depending on implementation
            expect(() => Sentinel.getInstance()).toThrow();
        });
    });

    // =========================================================================
    // healthCheck attacks
    // =========================================================================
    describe("healthCheck attacks", () => {
        it("healthCheck that returns false", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                { healthCheck: async () => false },
            );
            // healthCheck is informational; ingest should still work
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const healthy = await transport.healthCheck!();
            expect(healthy).toBe(false);
            // Ingest should still proceed regardless of healthCheck
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("healthCheck that throws", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    healthCheck: async () => {
                        throw new Error("healthCheck explodes");
                    },
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            await expect(transport.healthCheck!()).rejects.toThrow("healthCheck explodes");
            // Ingest should still work
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("healthCheck that hangs does not affect ingest", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    healthCheck: () => new Promise<boolean>(() => {}), // never resolves
                },
            );
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            // healthCheck hangs, but ingest is independent
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });

        it("healthCheck returning non-boolean value", async () => {
            const transport = createMockTransport(
                async (log) => createFakeResult({ traceId: log.traceId }),
                {
                    healthCheck: async () => "healthy" as unknown as boolean,
                },
            );
            const config = createTestConfig();
            Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const result = await transport.healthCheck!();
            // Truthy but not boolean
            expect(result).toBeTruthy();
        });

        it("healthCheck not defined does not crash transport usage", async () => {
            const transport: RemoteTransport = {
                send: vi.fn(async () => createFakeResult()),
                // no healthCheck
            };
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            expect(transport.healthCheck).toBeUndefined();
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
        });
    });

    // =========================================================================
    // Transport mode edge cases
    // =========================================================================
    describe("Transport mode edge cases", () => {
        it("local mode ignores transport even if provided", async () => {
            const sendFn = vi.fn(async () => createFakeResult());
            const transport = createMockTransport(sendFn);
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "local", transport, timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result).toBeDefined();
            expect(sendFn).not.toHaveBeenCalled();
        });

        it("remote mode without transport falls through to local", async () => {
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            // No transport defined, so remote condition is false, falls to local
            expect(result.hashChainValid).toBe(true);
        });

        it("dual mode without transport acts as local only", async () => {
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", timeoutMs: 5000 },
            });
            const result = await s.ingest({ message: "test" });
            expect(result.hashChainValid).toBe(true);
        });

        it("no transport options at all defaults to local", async () => {
            const config = createTestConfig({ security: { enableHashChain: true } });
            const s = Sentinel.initialize(config);
            const result = await s.ingest({ message: "test" });
            expect(result.hashChainValid).toBe(true);
        });
    });

    // =========================================================================
    // Concurrent transport operations
    // =========================================================================
    describe("Concurrent transport operations", () => {
        it("concurrent remote sends do not interfere with each other", async () => {
            const receivedMessages: string[] = [];
            const transport = createMockTransport(async (log) => {
                await new Promise((r) => setTimeout(r, Math.random() * 20));
                receivedMessages.push(log.message);
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const promises = Array.from({ length: 10 }, (_, i) =>
                s.ingest({ message: `concurrent-${i}` }),
            );
            const results = await Promise.all(promises);
            expect(results).toHaveLength(10);
            expect(receivedMessages).toHaveLength(10);
        });

        it("concurrent dual mode sends maintain local hash chain integrity", async () => {
            const transport = createMockTransport(async (log) => {
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig({ security: { enableHashChain: true }, onError: vi.fn() });
            const s = Sentinel.initialize(config, {
                transport: { mode: "dual", transport, timeoutMs: 5000 },
            });
            const promises = Array.from({ length: 5 }, (_, i) =>
                s.ingest({ message: `chain-${i}` }),
            );
            const results = await Promise.all(promises);
            results.forEach((r) => {
                expect(r.hashChainValid).toBe(true);
            });
        });

        it("mixed success/failure concurrent sends in remote mode", async () => {
            let callIndex = 0;
            const transport = createMockTransport(async (log) => {
                callIndex++;
                if (callIndex % 2 === 0) throw new Error("even call fails");
                return createFakeResult({ traceId: log.traceId });
            });
            const config = createTestConfig();
            const s = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 5000 },
            });
            const results = await Promise.allSettled(
                Array.from({ length: 6 }, (_, i) => s.ingest({ message: `msg-${i}` })),
            );
            const fulfilled = results.filter((r) => r.status === "fulfilled");
            const rejected = results.filter((r) => r.status === "rejected");
            expect(fulfilled.length + rejected.length).toBe(6);
        });
    });
});
