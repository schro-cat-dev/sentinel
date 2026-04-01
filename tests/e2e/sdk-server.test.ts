/**
 * Cross-component E2E test: TypeScript SDK -> gRPC -> Go Server
 *
 * This test suite builds the Go server binary, starts it as a child process,
 * and exercises the SDK's remote transport against the live server.
 *
 * Prerequisites:
 *   - Go toolchain installed
 *   - @grpc/grpc-js and @grpc/proto-loader available (installed as devDeps or locally)
 *
 * The suite is skipped entirely if Go is not available.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execSync, spawn, ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as net from "node:net";

// ---------------------------------------------------------------------------
// gRPC client type definitions (replaces `any` for dynamic proto-loader)
// ---------------------------------------------------------------------------

/** gRPC client instance with dynamic method dispatch */
interface GrpcClient {
    [method: string]: (
        request: Record<string, unknown>,
        callback: (err: Error | null, response: Record<string, unknown>) => void,
    ) => void;
}

/** Subset of @grpc/grpc-js used in this test */
interface GrpcModule {
    credentials: { createInsecure(): unknown };
    loadPackageDefinition(def: unknown): Record<string, unknown>;
    Metadata: new () => { set(key: string, value: string): void };
}

/** gRPC call response shapes */
interface HealthCheckResponse {
    status: string;
    version: string;
}

interface IngestResponse {
    traceId: string;
    hashChainValid: boolean;
    masked: boolean;
    tasksGenerated: Array<{ ruleId: string; status: string }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(__dirname, "../..");
const SERVER_PKG = join(PROJECT_ROOT, "packages/server");
const PROTO_PATH = join(SERVER_PKG, "proto/sentinel.proto");
const CONFIG_PATH = join(__dirname, "test-server-config.yaml");
const BINARY_PATH = join(tmpdir(), "sentinel-e2e-test-server");
const HMAC_KEY = "e2e-test-hmac-key-that-is-at-least-32-bytes-long!!";

/** Find a free TCP port by briefly listening on port 0. */
async function getFreePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.listen(0, "127.0.0.1", () => {
            const addr = srv.address();
            if (addr && typeof addr === "object") {
                const port = addr.port;
                srv.close(() => resolve(port));
            } else {
                srv.close(() => reject(new Error("Could not determine port")));
            }
        });
        srv.on("error", reject);
    });
}

/** Check if a command exists on the system PATH. */
function commandExists(cmd: string): boolean {
    try {
        execSync(`which ${cmd}`, { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
}

/**
 * Create a gRPC client for the Sentinel server using dynamic proto loading.
 * Returns { client, grpc } so the caller can build metadata etc.
 */
function createGrpcClient(serverAddr: string): { client: GrpcClient; grpc: GrpcModule } {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const grpc = require("@grpc/grpc-js") as GrpcModule;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const protoLoader = require("@grpc/proto-loader") as {
        loadSync(path: string, options: Record<string, unknown>): unknown;
    };

    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
        keepCase: false,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
    });
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const sentinel = protoDescriptor.sentinel as Record<string, Record<string, new (addr: string, creds: unknown) => GrpcClient>>;
    const SentinelService = sentinel.v1.SentinelService;
    const client = new SentinelService(serverAddr, grpc.credentials.createInsecure());
    return { client, grpc };
}

/** Promisified unary gRPC call. */
function grpcCall<TRes>(
    client: GrpcClient,
    method: string,
    request: Record<string, unknown>,
): Promise<TRes> {
    return new Promise((resolve, reject) => {
        client[method](request, (err: Error | null, response: Record<string, unknown>) => {
            if (err) reject(err);
            else resolve(response as TRes);
        });
    });
}

/** Wait until the server health check returns "SERVING", up to maxMs. */
async function waitForServer(client: GrpcClient, maxMs = 15_000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < maxMs) {
        try {
            const res = await grpcCall<HealthCheckResponse>(client, "HealthCheck", {});
            if (res.status === "SERVING") return;
        } catch {
            // Server not ready yet — retry
        }
        await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`Server did not become ready within ${maxMs}ms`);
}

// ---------------------------------------------------------------------------
// Guard: skip if Go or gRPC deps are unavailable
// ---------------------------------------------------------------------------

const HAS_GO = commandExists("go");

let HAS_GRPC_DEPS = false;
try {
    require.resolve("@grpc/grpc-js");
    require.resolve("@grpc/proto-loader");
    HAS_GRPC_DEPS = true;
} catch {
    // not installed
}

const describeE2E = HAS_GO && HAS_GRPC_DEPS ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describeE2E("E2E: TypeScript SDK <-> Go gRPC Server", () => {
    let serverProcess: ChildProcess | null = null;
    let serverPort: number;
    let serverAddr: string;
    let grpcClient: GrpcClient;
    let tmpDir: string;

    // SDK imports (resolved lazily to avoid import errors when skipped)
    let Sentinel: typeof import("../../src/index").Sentinel;
    let createDefaultConfig: typeof import("../../src/index").createDefaultConfig;
    let createGrpcTransport: typeof import("../../examples/grpc-transport").createGrpcTransport;

    beforeAll(async () => {
        // --- 1. Build Go binary ---
        console.log("[E2E] Building Go server binary...");
        execSync(`go build -o ${BINARY_PATH} ./cmd/server/`, {
            cwd: SERVER_PKG,
            stdio: "pipe",
            timeout: 120_000,
        });

        // --- 2. Prepare temp directory and config ---
        tmpDir = mkdtempSync(join(tmpdir(), "sentinel-e2e-"));
        serverPort = await getFreePort();
        serverAddr = `127.0.0.1:${serverPort}`;

        // Write a port-specific config (override addr in the yaml)
        const baseConfig = readFileSync(CONFIG_PATH, "utf-8");
        const patchedConfig = baseConfig.replace(
            /addr:\s*".*"/,
            `addr: ":${serverPort}"`,
        );
        const runtimeConfigPath = join(tmpDir, "sentinel-e2e.yaml");
        writeFileSync(runtimeConfigPath, patchedConfig);

        // --- 3. Start the server ---
        console.log(`[E2E] Starting server on ${serverAddr}...`);
        serverProcess = spawn(BINARY_PATH, ["-config", runtimeConfigPath], {
            env: {
                ...process.env,
                SENTINEL_HMAC_KEY: HMAC_KEY,
                SENTINEL_ADDR: `:${serverPort}`,
            },
            stdio: ["ignore", "pipe", "pipe"],
        });

        // Collect stderr/stdout for debugging on failure
        let serverStdout = "";
        let serverStderr = "";
        serverProcess.stdout?.on("data", (d: Buffer) => {
            serverStdout += d.toString();
        });
        serverProcess.stderr?.on("data", (d: Buffer) => {
            serverStderr += d.toString();
        });
        serverProcess.on("exit", (code) => {
            if (code !== null && code !== 0) {
                console.error(`[E2E] Server exited with code ${code}`);
                console.error("[E2E] stdout:", serverStdout);
                console.error("[E2E] stderr:", serverStderr);
            }
        });

        // --- 4. Wait for readiness ---
        const { client } = createGrpcClient(serverAddr);
        grpcClient = client;
        await waitForServer(grpcClient, 15_000);
        console.log("[E2E] Server is ready.");

        // --- 5. Lazy-load SDK modules ---
        const sdkModule = await import("../../src/index");
        Sentinel = sdkModule.Sentinel;
        createDefaultConfig = sdkModule.createDefaultConfig;
        const transportModule = await import("../../examples/grpc-transport");
        createGrpcTransport = transportModule.createGrpcTransport;
    }, 120_000); // generous timeout for go build

    afterAll(async () => {
        // Shut down gRPC client
        if (grpcClient) {
            try {
                grpcClient.close();
            } catch {
                // ignore
            }
        }

        // Kill server process
        if (serverProcess && !serverProcess.killed) {
            serverProcess.kill("SIGTERM");
            // Give it a moment for graceful shutdown
            await new Promise<void>((resolve) => {
                const timeout = setTimeout(() => {
                    if (serverProcess && !serverProcess.killed) {
                        serverProcess.kill("SIGKILL");
                    }
                    resolve();
                }, 5_000);
                serverProcess!.on("exit", () => {
                    clearTimeout(timeout);
                    resolve();
                });
            });
        }

        // Clean up binary and temp dir
        try {
            rmSync(BINARY_PATH, { force: true });
        } catch {
            // ignore
        }
        try {
            rmSync(tmpDir, { recursive: true, force: true });
        } catch {
            // ignore
        }

        // Reset SDK singleton
        try {
            Sentinel?.reset();
        } catch {
            // ignore
        }
    }, 15_000);

    // ------------------------------------------------------------------
    // Scenario 1: Basic log ingestion via remote mode
    // ------------------------------------------------------------------
    describe("Basic log ingestion (remote mode)", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("sends a log through the SDK and receives a valid response from the server", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                security: { enableHashChain: true },
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                    preserveFields: ["traceId"],
                },
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            const result = await sentinel.ingest({
                message: "E2E test: basic log ingestion",
                level: 3,
                type: "SYSTEM",
                boundary: "e2e-test:basic",
            });

            expect(result).toBeDefined();
            expect(result.traceId).toBeTruthy();
            expect(typeof result.traceId).toBe("string");
            expect(typeof result.hashChainValid).toBe("boolean");
            expect(typeof result.masked).toBe("boolean");
            expect(Array.isArray(result.tasksGenerated)).toBe(true);

            await transport.close?.();
        });

        it("returns hash_chain_valid=true for a valid log", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                security: { enableHashChain: true },
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            const result = await sentinel.ingest({
                message: "Hash chain test log",
                level: 3,
            });

            expect(result.hashChainValid).toBe(true);

            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Scenario 2: PII masking verification
    // ------------------------------------------------------------------
    describe("PII masking", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("masks PII in log message on the server side", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            const result = await sentinel.ingest({
                message: "Contact admin@example.com for support",
                level: 3,
                type: "SYSTEM",
            });

            // The server has masking enabled, so it should report masked=true
            expect(result.masked).toBe(true);
            expect(result.traceId).toBeTruthy();

            await transport.close?.();
        });

        it("reports masked=true when PII patterns are present in message", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            const result = await sentinel.ingest({
                message: "User phone: 090-1234-5678, card: 4111-1111-1111-1111",
                level: 4,
                type: "COMPLIANCE",
            });

            expect(result.masked).toBe(true);

            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Scenario 3: Hash chain integrity across multiple logs
    // ------------------------------------------------------------------
    describe("Hash chain integrity", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("maintains hash chain validity across multiple sequential logs", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                security: { enableHashChain: true },
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            const results = [];
            for (let i = 0; i < 5; i++) {
                const result = await sentinel.ingest({
                    message: `Hash chain log entry ${i}`,
                    level: 3,
                    type: "SYSTEM",
                });
                results.push(result);
            }

            // All logs should have valid hash chains
            for (const result of results) {
                expect(result.hashChainValid).toBe(true);
                expect(result.traceId).toBeTruthy();
            }

            // All trace IDs should be unique
            const traceIds = results.map((r) => r.traceId);
            expect(new Set(traceIds).size).toBe(5);

            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Scenario 4: Error handling (invalid log rejection)
    // ------------------------------------------------------------------
    describe("Error handling", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("rejects empty message on the SDK side (validation)", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport },
            });

            // SDK-level validation should reject before hitting the server
            await expect(sentinel.ingest({ message: "" })).rejects.toThrow();

            await transport.close?.();
        });

        it("handles connection to non-existent server gracefully", async () => {
            Sentinel.reset();
            const deadPort = await getFreePort();
            const transport = createGrpcTransport(`127.0.0.1:${deadPort}`);
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: {
                    mode: "remote",
                    transport,
                    timeoutMs: 3_000,
                },
            });

            await expect(
                sentinel.ingest({ message: "Should fail to connect" }),
            ).rejects.toThrow();

            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Scenario 5: Dual mode (local + remote processing)
    // ------------------------------------------------------------------
    describe("Dual mode (local + remote)", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("processes log both locally and remotely in dual mode", async () => {
            Sentinel.reset();
            const transport = createGrpcTransport(serverAddr);

            const processedLogs: import("../../src/types/log").Log[] = [];
            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                security: { enableHashChain: true },
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                    preserveFields: ["traceId"],
                },
                taskRules: [],
                onLogProcessed: (log) => processedLogs.push(log),
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "dual", transport },
            });

            const result = await sentinel.ingest({
                message: "Dual mode test: user@test.com",
                level: 3,
                type: "SYSTEM",
            });

            // Local processing should have happened
            expect(processedLogs.length).toBeGreaterThanOrEqual(1);
            const localLog = processedLogs[0];
            expect(localLog.message).not.toContain("user@test.com");
            expect(localLog.message).toContain("[MASKED_EMAIL]");

            // Result comes from local processing in dual mode
            expect(result).toBeDefined();
            expect(result.traceId).toBeTruthy();
            expect(result.masked).toBe(true);

            await transport.close?.();
        });

        it("returns local result even if remote fails in dual mode", async () => {
            Sentinel.reset();
            const deadPort = await getFreePort();
            const transport = createGrpcTransport(`127.0.0.1:${deadPort}`);

            const config = createDefaultConfig({
                projectName: "e2e-test",
                serviceId: "e2e-sdk",
                environment: "test",
                security: { enableHashChain: true },
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: {
                    mode: "dual",
                    transport,
                    timeoutMs: 2_000,
                },
            });

            // In dual mode, local result is returned even if remote fails
            const result = await sentinel.ingest({
                message: "Dual mode with dead remote",
                level: 3,
            });

            expect(result).toBeDefined();
            expect(result.traceId).toBeTruthy();
            expect(result.hashChainValid).toBe(true);

            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Scenario 6: Transport timeout handling
    // ------------------------------------------------------------------
    describe("Transport timeout", () => {
        afterAll(() => {
            try {
                Sentinel?.reset();
            } catch {
                // ignore
            }
        });

        it("times out when remote transport exceeds configured timeout", async () => {
            Sentinel.reset();

            // Create a TCP server that accepts connections but never responds
            const blackHoleServer = net.createServer((socket) => {
                // Accept connection but do nothing — causes the gRPC call to hang
                socket.on("error", () => {
                    // swallow
                });
            });

            const blackHolePort = await getFreePort();
            await new Promise<void>((resolve) => {
                blackHoleServer.listen(blackHolePort, "127.0.0.1", () => resolve());
            });

            try {
                const transport = createGrpcTransport(`127.0.0.1:${blackHolePort}`);
                const config = createDefaultConfig({
                    projectName: "e2e-test",
                    serviceId: "e2e-sdk",
                    environment: "test",
                    taskRules: [],
                });

                const sentinel = Sentinel.initialize(config, {
                    transport: {
                        mode: "remote",
                        transport,
                        timeoutMs: 1_000,
                    },
                });

                await expect(
                    sentinel.ingest({ message: "Should timeout" }),
                ).rejects.toThrow(/[Tt]imeout/);

                await transport.close?.();
            } finally {
                blackHoleServer.close();
            }
        }, 10_000);

        it("falls back to local when remote times out and fallbackToLocal is enabled", async () => {
            Sentinel.reset();

            const blackHoleServer = net.createServer((socket) => {
                socket.on("error", () => {
                    // swallow
                });
            });

            const blackHolePort = await getFreePort();
            await new Promise<void>((resolve) => {
                blackHoleServer.listen(blackHolePort, "127.0.0.1", () => resolve());
            });

            try {
                const transport = createGrpcTransport(`127.0.0.1:${blackHolePort}`);
                const config = createDefaultConfig({
                    projectName: "e2e-test",
                    serviceId: "e2e-sdk",
                    environment: "test",
                    security: { enableHashChain: true },
                    taskRules: [],
                });

                const sentinel = Sentinel.initialize(config, {
                    transport: {
                        mode: "remote",
                        transport,
                        fallbackToLocal: true,
                        timeoutMs: 1_000,
                    },
                });

                // With fallback, should succeed via local processing
                const result = await sentinel.ingest({
                    message: "Fallback on timeout",
                    level: 3,
                });

                expect(result).toBeDefined();
                expect(result.traceId).toBeTruthy();

                await transport.close?.();
            } finally {
                blackHoleServer.close();
            }
        }, 10_000);
    });

    // ------------------------------------------------------------------
    // Bonus: Direct gRPC health check
    // ------------------------------------------------------------------
    describe("Server health check", () => {
        it("returns SERVING status via gRPC health check", async () => {
            const res = await grpcCall<HealthCheckResponse>(grpcClient, "HealthCheck", {});
            expect(res.status).toBe("SERVING");
            expect(res.version).toBeTruthy();
        });

        it("returns SERVING via the transport healthCheck helper", async () => {
            const transport = createGrpcTransport(serverAddr);
            const healthy = await transport.healthCheck?.();
            expect(healthy).toBe(true);
            await transport.close?.();
        });
    });

    // ------------------------------------------------------------------
    // Bonus: Direct gRPC ingest to verify server response shape
    // ------------------------------------------------------------------
    describe("Direct gRPC ingest", () => {
        it("returns expected response fields from a direct gRPC ingest call", async () => {
            const res = await grpcCall<IngestResponse>(grpcClient, "Ingest", {
                traceId: "",
                type: "SYSTEM",
                level: 3,
                boundary: "e2e-direct-test",
                serviceId: "e2e-sdk",
                isCritical: false,
                message: "Direct gRPC test message with email test@e2e.com",
                origin: "SYSTEM",
                tags: [],
                actorId: "",
                spanId: "",
                parentSpanId: "",
                resourceIds: [],
                input: "",
                triggerAgent: false,
            });

            expect(res.traceId).toBeTruthy();
            expect(res.hashChainValid).toBe(true);
            expect(res.masked).toBe(true);
            expect(Array.isArray(res.tasksGenerated)).toBe(true);
        });

        it("generates tasks for critical logs via direct gRPC", async () => {
            const res = await grpcCall<IngestResponse>(grpcClient, "Ingest", {
                traceId: "",
                type: "SYSTEM",
                level: 6,
                boundary: "e2e-direct-test:critical",
                serviceId: "e2e-sdk",
                isCritical: true,
                message: "Critical failure in E2E test",
                origin: "SYSTEM",
                tags: [],
                actorId: "",
                spanId: "",
                parentSpanId: "",
                resourceIds: [],
                input: "",
                triggerAgent: false,
            });

            expect(res.traceId).toBeTruthy();
            expect(res.hashChainValid).toBe(true);
            expect(res.tasksGenerated.length).toBeGreaterThan(0);
            expect(res.tasksGenerated[0].ruleId).toBe("crit-notify");
            expect(res.tasksGenerated[0].status).toBe("dispatched");
        });
    });
});
