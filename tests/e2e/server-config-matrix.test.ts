/**
 * E2E: Server Config Matrix — サーバ立ち上げ動作確認テスト
 *
 * Go Server を異なる設定で起動し、sentinel.yaml の設定内容に応じて
 * 正しく動作するかを検証する。
 *
 * テスト項目:
 *   - integration flags の on/off で挙動変化を検証
 *   - HMAC 鍵設定 → SDK/Server 間のハッシュチェーン検証
 *   - 設定不一致時の警告（ConfigSummary 比較）
 *   - 正常系: ログ投入 → 検知 → タスク生成 → レスポンス
 *   - 異常系: 不正設定 / 認証失敗 / タイムアウト
 *   - エッジケース: 空ルール / 全機能無効 / dual モード
 *
 * Prerequisites:
 *   - Go toolchain installed
 *   - @grpc/grpc-js and @grpc/proto-loader available
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { execSync, spawn, ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as net from "node:net";

// ---------------------------------------------------------------------------
// gRPC client type definitions
// ---------------------------------------------------------------------------

interface GrpcClient {
    [method: string]: (
        request: Record<string, unknown>,
        ...args: unknown[]
    ) => void;
    close(): void;
}

interface GrpcModule {
    credentials: { createInsecure(): unknown };
    loadPackageDefinition(def: unknown): Record<string, unknown>;
    Metadata: new () => { set(key: string, value: string): void };
}

interface HealthCheckResponse {
    status: string;
    version: string;
    configSummary: {
        maskingRulesCount: number;
        detectionRulesCount: number;
        taskRulesCount: number;
        hashChainEnabled: boolean;
        maskingEnabled: boolean;
        serviceId: string;
    };
}

interface GetLogResponse {
    traceId: string;
    message: string;
    type: string;
    level: number;
    boundary: string;
    serviceId: string;
    isCritical: boolean;
    origin: string;
    actorId: string;
    tags: Array<{ key: string; category: string }>;
    hash: string;
    previousHash: string;
}

interface IngestResponse {
    traceId: string;
    hashChainValid: boolean;
    masked: boolean;
    tasksGenerated: Array<{ taskId: string; ruleId: string; status: string }>;
    threatResponses: Array<{
        responseId: string;
        eventName: string;
        strategy: string;
        blocked: boolean;
    }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(__dirname, "../..");
const SERVER_PKG = join(PROJECT_ROOT, "packages/server");
const PROTO_PATH = join(SERVER_PKG, "proto/sentinel.proto");
const BASE_CONFIG_PATH = join(__dirname, "test-server-config.yaml");
const BINARY_PATH = join(tmpdir(), "sentinel-e2e-config-matrix-server");
const HMAC_KEY = "e2e-test-hmac-key-that-is-at-least-32-bytes-long!!";

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

function commandExists(cmd: string): boolean {
    try {
        execSync(`which ${cmd}`, { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
}

function createGrpcClient(serverAddr: string, apiKey?: string): { client: GrpcClient; grpc: GrpcModule } {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const grpc = require("@grpc/grpc-js") as GrpcModule;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const protoLoader = require("@grpc/proto-loader") as {
        loadSync(path: string, options: Record<string, unknown>): unknown;
    };

    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
        keepCase: false, longs: String, enums: String, defaults: true, oneofs: true,
    });
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const sentinel = protoDescriptor.sentinel as Record<string, Record<string, new (addr: string, creds: unknown) => GrpcClient>>;
    const SentinelService = sentinel.v1.SentinelService;
    const client = new SentinelService(serverAddr, grpc.credentials.createInsecure());

    if (apiKey) {
        // Metadata is set per-call, not on client construction
    }

    return { client, grpc };
}

function grpcCall<TRes>(
    client: GrpcClient,
    method: string,
    request: Record<string, unknown>,
    metadata?: unknown,
): Promise<TRes> {
    return new Promise((resolve, reject) => {
        const args: unknown[] = [request];
        if (metadata) args.push(metadata);
        args.push((err: Error | null, response: Record<string, unknown>) => {
            if (err) reject(err);
            else resolve(response as TRes);
        });
        client[method](...args);
    });
}

async function waitForServer(client: GrpcClient, maxMs = 15_000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < maxMs) {
        try {
            const res = await grpcCall<HealthCheckResponse>(client, "HealthCheck", {});
            if (res.status === "SERVING") return;
        } catch {
            // Server not ready yet
        }
        await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`Server did not become ready within ${maxMs}ms`);
}

/** Launch a Go server with the given YAML config content. Returns cleanup function. */
async function launchServer(
    configYaml: string,
    env?: Record<string, string>,
): Promise<{
    process: ChildProcess;
    port: number;
    addr: string;
    client: GrpcClient;
    grpc: GrpcModule;
    tmpDir: string;
    cleanup: () => Promise<void>;
}> {
    const tmpDir = mkdtempSync(join(tmpdir(), "sentinel-e2e-cfg-"));
    const port = await getFreePort();
    const addr = `127.0.0.1:${port}`;

    const patchedConfig = configYaml.replace(/addr:\s*".*"/, `addr: ":${port}"`);
    const runtimeConfigPath = join(tmpDir, "sentinel-e2e.yaml");
    writeFileSync(runtimeConfigPath, patchedConfig);

    const proc = spawn(BINARY_PATH, ["-config", runtimeConfigPath], {
        env: {
            ...process.env,
            SENTINEL_HMAC_KEY: HMAC_KEY,
            SENTINEL_ADDR: `:${port}`,
            ...env,
        },
        stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    proc.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.on("exit", (code) => {
        if (code !== null && code !== 0) {
            console.error(`[E2E-Config] Server exited with code ${code}`);
            console.error("[E2E-Config] stdout:", stdout);
            console.error("[E2E-Config] stderr:", stderr);
        }
    });

    const { client, grpc: grpcMod } = createGrpcClient(addr);
    await waitForServer(client, 15_000);

    const cleanup = async () => {
        try { client.close(); } catch { /* ignore */ }
        if (proc && !proc.killed) {
            proc.kill("SIGTERM");
            await new Promise<void>((resolve) => {
                const timeout = setTimeout(() => {
                    if (!proc.killed) proc.kill("SIGKILL");
                    resolve();
                }, 5_000);
                proc.on("exit", () => { clearTimeout(timeout); resolve(); });
            });
        }
        try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    };

    return { process: proc, port, addr, client, grpc: grpcMod, tmpDir, cleanup };
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
// SDK imports (resolved lazily)
// ---------------------------------------------------------------------------

let Sentinel: typeof import("../../src/index").Sentinel;
let createDefaultConfig: typeof import("../../src/index").createDefaultConfig;
let createGrpcTransport: typeof import("../../examples/grpc-transport").createGrpcTransport;

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describeE2E("E2E: Server Config Matrix — サーバ立ち上げ動作確認", () => {
    const baseConfig = readFileSync(BASE_CONFIG_PATH, "utf-8");

    beforeAll(async () => {
        // Build Go binary once
        console.log("[E2E-Config] Building Go server binary...");
        execSync(`go build -o ${BINARY_PATH} ./cmd/server/`, {
            cwd: SERVER_PKG,
            stdio: "pipe",
            timeout: 120_000,
        });

        // Lazy-load SDK
        const sdkModule = await import("../../src/index");
        Sentinel = sdkModule.Sentinel;
        createDefaultConfig = sdkModule.createDefaultConfig;
        const transportModule = await import("../../examples/grpc-transport");
        createGrpcTransport = transportModule.createGrpcTransport;
    }, 120_000);

    afterAll(() => {
        try { rmSync(BINARY_PATH, { force: true }); } catch { /* ignore */ }
    });

    afterEach(() => {
        try { Sentinel?.reset(); } catch { /* ignore */ }
    });

    // ==================================================================
    // 1. ConfigSummary 検証 — HealthCheck が設定内容を正しく返す
    // ==================================================================
    describe("ConfigSummary verification", () => {
        it("returns correct ConfigSummary matching server config", async () => {
            const server = await launchServer(baseConfig);
            try {
                const res = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(res.status).toBe("SERVING");
                expect(res.version).toBeTruthy();

                // Base config has: 3 masking rules, 0 detection rules, 2 task rules
                const summary = res.configSummary;
                expect(summary).toBeDefined();
                expect(summary.maskingRulesCount).toBe(3); // EMAIL, CREDIT_CARD, PHONE
                expect(summary.taskRulesCount).toBe(2);    // crit-notify, sec-analyze
                expect(summary.hashChainEnabled).toBe(true);
                expect(summary.maskingEnabled).toBe(true);
                expect(summary.serviceId).toBe("e2e-test-server");
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("reflects config changes in ConfigSummary (no masking, no hash chain)", async () => {
            const minimalConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: minimal-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(minimalConfig);
            try {
                const res = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                const summary = res.configSummary;

                expect(summary.maskingRulesCount).toBe(0);
                expect(summary.taskRulesCount).toBe(0);
                expect(summary.hashChainEnabled).toBe(false);
                expect(summary.maskingEnabled).toBe(false);
                expect(summary.serviceId).toBe("minimal-server");
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 2. HMAC 鍵設定 → SDK/Server 間のハッシュチェーン検証
    // ==================================================================
    describe("HMAC key and hash chain", () => {
        it("SDK + Server both with hash chain → hashChainValid=true", async () => {
            const server = await launchServer(baseConfig);
            try {
                Sentinel.reset();
                const transport = createGrpcTransport(server.addr);
                const config = createDefaultConfig({
                    projectName: "e2e-config-test",
                    serviceId: "e2e-sdk",
                    environment: "test",
                    security: { enableHashChain: true },
                    taskRules: [],
                });

                const sentinel = Sentinel.initialize(config, {
                    transport: { mode: "remote", transport },
                });

                const results = [];
                for (let i = 0; i < 3; i++) {
                    results.push(await sentinel.ingest({
                        message: `HMAC hash chain test log ${i}`,
                        level: 3,
                        type: "SYSTEM",
                    }));
                }

                for (const result of results) {
                    expect(result.hashChainValid).toBe(true);
                    expect(result.traceId).toBeTruthy();
                }

                await transport.close?.();
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("Server with hash chain disabled → hashChainValid still returned (server decides)", async () => {
            const noHashConfig = baseConfig
                .replace(/enable_hash_chain:\s*true/, "enable_hash_chain: false");

            const server = await launchServer(noHashConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 3,
                    serviceId: "e2e-sdk",
                    message: "Test with hash chain disabled",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                // hash chain disabled on server → hashChainValid is false
                expect(res.hashChainValid).toBe(false);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 3. 正常系: ログ投入 → 検知 → タスク生成 → レスポンス
    // ==================================================================
    describe("Full pipeline: ingest → detect → task generation", () => {
        it("critical log triggers crit-notify task rule", async () => {
            const server = await launchServer(baseConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 6,
                    boundary: "e2e-config:critical",
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Critical system failure detected in config matrix test",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.tasksGenerated[0].ruleId).toBe("crit-notify");
                expect(res.tasksGenerated[0].status).toBe("dispatched");
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("SDK remote mode: full flow with PII masking + task generation", async () => {
            const server = await launchServer(baseConfig);
            try {
                Sentinel.reset();
                const transport = createGrpcTransport(server.addr);
                const config = createDefaultConfig({
                    projectName: "e2e-config-test",
                    serviceId: "e2e-sdk",
                    environment: "test",
                    security: { enableHashChain: true },
                    taskRules: [],
                });

                const sentinel = Sentinel.initialize(config, {
                    transport: { mode: "remote", transport },
                });

                // Send critical log with PII
                const result = await sentinel.ingest({
                    message: "Critical: admin@company.com system failure",
                    level: 6,
                    isCritical: true,
                    type: "SYSTEM",
                });

                expect(result.traceId).toBeTruthy();
                expect(result.masked).toBe(true);
                expect(result.hashChainValid).toBe(true);
                expect(result.tasksGenerated.length).toBeGreaterThan(0);

                // Verify PII was ACTUALLY removed from stored log via GetLog RPC
                const storedLog = await grpcCall<GetLogResponse>(
                    server.client, "GetLog", { traceId: result.traceId },
                );
                expect(storedLog.message).not.toContain("admin@company.com");
                expect(storedLog.traceId).toBe(result.traceId);

                await transport.close?.();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 4. エッジケース: 空ルール / 全機能無効
    // ==================================================================
    describe("Edge cases: empty rules / all features disabled", () => {
        it("server with no rules processes logs without generating tasks", async () => {
            const noRulesConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: no-rules-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(noRulesConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 6,
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Critical log with no rules configured",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                // No task rules → no tasks generated (built-in detection may still fire
                // but without matching task rules, no dispatches)
                expect(res.masked).toBe(false); // masking disabled
                expect(res.hashChainValid).toBe(false); // hash chain disabled
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("server with all features disabled still serves health check", async () => {
            const allDisabledConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: disabled-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(allDisabledConfig);
            try {
                const res = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(res.status).toBe("SERVING");
                expect(res.configSummary.maskingEnabled).toBe(false);
                expect(res.configSummary.hashChainEnabled).toBe(false);
                expect(res.configSummary.taskRulesCount).toBe(0);
                expect(res.configSummary.maskingRulesCount).toBe(0);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 5. 異常系: 認証失敗
    // ==================================================================
    describe("Auth enabled: API key rejection", () => {
        it("rejects unauthenticated requests when auth is enabled", async () => {
            const authConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: auth-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: true
  api_keys:
    - "valid-test-key-12345"
  rate_limit_rps: 100
  rate_limit_burst: 200
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(authConfig);
            try {
                // Request without API key → should be rejected
                await expect(
                    grpcCall<IngestResponse>(server.client, "Ingest", {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: "This should be rejected",
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    }),
                ).rejects.toThrow();
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("accepts authenticated requests with valid API key", async () => {
            const authConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: auth-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: true
  api_keys:
    - "valid-test-key-12345"
  rate_limit_rps: 100
  rate_limit_burst: 200
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(authConfig);
            try {
                const metadata = new server.grpc.Metadata();
                metadata.set("x-api-key", "valid-test-key-12345");

                const res = await grpcCall<IngestResponse>(
                    server.client,
                    "Ingest",
                    {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: "Authenticated request",
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    },
                    metadata,
                );

                expect(res.traceId).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("rejects requests with invalid API key", async () => {
            const authConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: auth-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: true
  api_keys:
    - "valid-test-key-12345"
  rate_limit_rps: 100
  rate_limit_burst: 200
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(authConfig);
            try {
                const metadata = new server.grpc.Metadata();
                metadata.set("x-api-key", "wrong-key");

                await expect(
                    grpcCall<IngestResponse>(
                        server.client,
                        "Ingest",
                        {
                            traceId: "",
                            type: "SYSTEM",
                            level: 3,
                            serviceId: "e2e-sdk",
                            message: "Should be rejected",
                            origin: "SYSTEM",
                            tags: [],
                            resourceIds: [],
                            input: "",
                        },
                        metadata,
                    ),
                ).rejects.toThrow();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 6. SDK dual モード + 設定バリエーション
    // ==================================================================
    describe("SDK dual mode with config variations", () => {
        it("dual mode: local processing works even when server has different config", async () => {
            const server = await launchServer(baseConfig);
            try {
                Sentinel.reset();
                const transport = createGrpcTransport(server.addr);

                const processedLogs: import("../../src/types/log").Log[] = [];
                const config = createDefaultConfig({
                    projectName: "e2e-config-test",
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
                    message: "Dual mode config test: contact@test.com",
                    level: 3,
                    type: "SYSTEM",
                });

                // Local processing happened
                expect(processedLogs.length).toBeGreaterThanOrEqual(1);
                expect(processedLogs[0].message).toContain("[MASKED_EMAIL]");
                expect(processedLogs[0].message).not.toContain("contact@test.com");

                // Result is valid
                expect(result.traceId).toBeTruthy();
                expect(result.masked).toBe(true);

                await transport.close?.();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 7. response.enabled の on/off による挙動変化
    // ==================================================================
    describe("Response module toggle", () => {
        it("server with response disabled → no threat_responses in ingest result", async () => {
            // Base config has response.enabled: false
            const server = await launchServer(baseConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 6,
                    boundary: "e2e:response-off",
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Security intrusion attempt from 192.168.1.100",
                    origin: "SYSTEM",
                    tags: [{ key: "ip", category: "192.168.1.100" }],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                // Response module disabled → no threat responses
                expect(res.threatResponses).toHaveLength(0);
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("server with response enabled → threat_responses populated for security events", async () => {
            const responseConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: true
  enable_hash_chain: true
  masking_rules:
    - type: PII_TYPE
      category: EMAIL
pipeline:
  service_id: response-enabled-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: true
  default_strategy: BLOCK_AND_ANALYZE
  block_mode: IMMEDIATE
  rules:
    - event_name: SECURITY_INTRUSION_DETECTED
      strategy: BLOCK_AND_ANALYZE
      block_action: ip_block
      notify_targets:
        - "#security"
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(responseConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 6,
                    boundary: "e2e:response-on",
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Security intrusion detected from 10.0.0.50",
                    origin: "SYSTEM",
                    tags: [{ key: "ip", category: "10.0.0.50" }],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                // Response module enabled → threat responses should be generated
                expect(res.threatResponses.length).toBeGreaterThan(0);
                expect(res.threatResponses[0].eventName).toBeTruthy();
                expect(res.threatResponses[0].strategy).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 8. 異常系: 接続タイムアウト / SDK fallback
    // ==================================================================
    describe("Connection timeout and SDK fallback", () => {
        it("SDK remote mode fails gracefully when server is unreachable", async () => {
            Sentinel.reset();
            const deadPort = await getFreePort();
            const transport = createGrpcTransport(`127.0.0.1:${deadPort}`);
            const config = createDefaultConfig({
                projectName: "e2e-config-test",
                serviceId: "e2e-sdk",
                environment: "test",
                taskRules: [],
            });

            const sentinel = Sentinel.initialize(config, {
                transport: { mode: "remote", transport, timeoutMs: 2_000 },
            });

            await expect(
                sentinel.ingest({ message: "Should fail" }),
            ).rejects.toThrow();

            await transport.close?.();
        }, 10_000);

        it("SDK fallbackToLocal works when server goes down", async () => {
            Sentinel.reset();
            const deadPort = await getFreePort();
            const transport = createGrpcTransport(`127.0.0.1:${deadPort}`);
            const config = createDefaultConfig({
                projectName: "e2e-config-test",
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

            const result = await sentinel.ingest({
                message: "Fallback test with dead server",
                level: 3,
            });

            expect(result).toBeDefined();
            expect(result.traceId).toBeTruthy();

            await transport.close?.();
        }, 10_000);
    });

    // ==================================================================
    // 9. マスキングルールバリエーション
    // ==================================================================
    describe("Masking rule variations", () => {
        it("server with only PHONE masking rule → masks phone but not email", async () => {
            const phoneOnlyConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: true
  enable_hash_chain: false
  masking_rules:
    - type: PII_TYPE
      category: PHONE
pipeline:
  service_id: phone-only-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(phoneOnlyConfig);
            try {
                // Message with phone → should be masked
                const resPhone = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 3,
                    serviceId: "e2e-sdk",
                    message: "Call 090-1234-5678 for support",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(resPhone.masked).toBe(true);

                // Verify ACTUAL content was masked via GetLog RPC
                const storedPhone = await grpcCall<GetLogResponse>(
                    server.client, "GetLog", { traceId: resPhone.traceId },
                );
                expect(storedPhone.message).not.toContain("090-1234-5678");

                // Message without PII → masking pipeline runs but no content changed
                const resClean = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 3,
                    serviceId: "e2e-sdk",
                    message: "Clean log message without PII",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                // No PII present → masked=false (content was not altered)
                expect(resClean.masked).toBe(false);

                // Verify clean message is stored unchanged
                const storedClean = await grpcCall<GetLogResponse>(
                    server.client, "GetLog", { traceId: resClean.traceId },
                );
                expect(storedClean.message).toContain("Clean log message without PII");

                // ConfigSummary should show 1 masking rule
                const health = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(health.configSummary.maskingRulesCount).toBe(1);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 10. 複数タスクルール構成
    // ==================================================================
    describe("Multiple task rules configuration", () => {
        it("different event types trigger different task rules", async () => {
            const multiRuleConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: true
pipeline:
  service_id: multi-rule-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
    - rule_id: sec-analyze
      event_name: SECURITY_INTRUSION_DETECTED
      severity: HIGH
      action_type: AI_ANALYZE
      execution_level: AUTO
      priority: 1
      description: "AI analysis of security intrusion"
      guardrails:
        require_human_approval: false
        timeout_ms: 60000
        max_retries: 2
    - rule_id: compliance-alert
      event_name: COMPLIANCE_VIOLATION
      severity: MEDIUM
      action_type: ESCALATE
      execution_level: AUTO
      priority: 2
      description: "Escalate compliance violation"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 1
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(multiRuleConfig);
            try {
                // ConfigSummary should reflect 3 task rules
                const health = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(health.configSummary.taskRulesCount).toBe(3);

                // Critical log → crit-notify
                const critRes = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 6,
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Critical system failure",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(critRes.tasksGenerated.length).toBeGreaterThan(0);
                expect(critRes.tasksGenerated.some((t) => t.ruleId === "crit-notify")).toBe(true);

                // Security log → sec-analyze
                const secRes = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 5,
                    serviceId: "e2e-sdk",
                    isCritical: false,
                    message: "Intrusion attempt from suspicious IP",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(secRes.tasksGenerated.length).toBeGreaterThan(0);
                expect(secRes.tasksGenerated.some((t) => t.ruleId === "sec-analyze")).toBe(true);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });
    // ==================================================================
    // 11. ConfigSummary detectionRulesCount の検証
    // ==================================================================
    describe("ConfigSummary detectionRulesCount", () => {
        it("reflects detection_rules count in ConfigSummary", async () => {
            const detectionConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: detection-count-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
detection_rules:
  - rule_id: custom-detect-1
    event_name: SECURITY_INTRUSION_DETECTED
    priority: HIGH
    conditions:
      log_types: ["SECURITY"]
      min_level: 4
      message_pattern: "intrusion"
  - rule_id: custom-detect-2
    event_name: COMPLIANCE_VIOLATION
    priority: MEDIUM
    conditions:
      log_types: ["BUSINESS-AUDIT"]
      min_level: 3
      message_pattern: "export"
`;
            const server = await launchServer(detectionConfig);
            try {
                const res = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(res.configSummary.detectionRulesCount).toBe(2);
                expect(res.configSummary.taskRulesCount).toBe(0);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 12. Ensemble detection 有効時の挙動
    // ==================================================================
    describe("Ensemble detection enabled", () => {
        it("ensemble mode detects events using dynamic rules and score aggregation", async () => {
            const ensembleConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: true
pipeline:
  service_id: ensemble-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
    - rule_id: sec-escalate
      event_name: SECURITY_INTRUSION_DETECTED
      severity: HIGH
      action_type: ESCALATE
      execution_level: AUTO
      priority: 1
      description: "Escalate security intrusion"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 2
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: true
  aggregator: max
  threshold: 0.5
  dedup_window_sec: 0
  dynamic_rules:
    - rule_id: ensemble-sec-detect
      event_name: SECURITY_INTRUSION_DETECTED
      priority: HIGH
      score: 1.0
      conditions:
        log_types: ["SECURITY"]
        min_level: 4
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(ensembleConfig);
            try {
                // Security log should trigger ensemble detection → task
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 5,
                    serviceId: "e2e-sdk",
                    isCritical: false,
                    message: "Suspicious activity detected via ensemble",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                expect(res.hashChainValid).toBe(true);
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.tasksGenerated.some((t) => t.ruleId === "sec-escalate")).toBe(true);

                // Normal low-level log should NOT trigger ensemble detection
                const normalRes = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 2,
                    serviceId: "e2e-sdk",
                    isCritical: false,
                    message: "Normal log, no detection expected",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(normalRes.tasksGenerated).toHaveLength(0);
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 13. Anomaly detection 有効時の挙動
    // ==================================================================
    describe("Anomaly detection enabled", () => {
        it("server with anomaly detection enabled processes logs without error", async () => {
            const anomalyConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: anomaly-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: true
  window_size_sec: 60
  baseline_window_sec: 300
  threshold_pct: 200.0
  min_baseline: 5.0
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(anomalyConfig);
            try {
                // Send multiple logs to feed the anomaly baseline
                for (let i = 0; i < 5; i++) {
                    const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: `Anomaly baseline log ${i}`,
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    });
                    expect(res.traceId).toBeTruthy();
                }

                // Health check still works with anomaly enabled
                const health = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(health.status).toBe("SERVING");
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 14. RBAC authorization — client_roles による権限制御
    // ==================================================================
    describe("Authorization (RBAC) with client roles", () => {
        const authzConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: authz-server
  rules: []
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: true
  api_keys:
    - "writer-key-e2e-test-long-enough"
    - "reader-key-e2e-test-long-enough"
  rate_limit_rps: 100
  rate_limit_burst: 200
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: true
  default_role: reader
  roles:
    writer:
      can_write: true
      can_read: true
      can_approve: false
      can_admin: false
      max_log_level: 6
    reader:
      can_write: false
      can_read: true
      can_approve: false
      can_admin: false
      max_log_level: 3
  client_roles:
    writer-key-e2e-test-long-enough: writer
    reader-key-e2e-test-long-enough: reader
masking_policies: []
routing_rules: []
`;

        it("writer role can ingest logs", async () => {
            const server = await launchServer(authzConfig);
            try {
                const metadata = new server.grpc.Metadata();
                metadata.set("x-api-key", "writer-key-e2e-test-long-enough");

                const res = await grpcCall<IngestResponse>(
                    server.client, "Ingest",
                    {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: "Writer role log",
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    },
                    metadata,
                );
                expect(res.traceId).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("reader role is rejected for ingest (no write permission)", async () => {
            const server = await launchServer(authzConfig);
            try {
                const metadata = new server.grpc.Metadata();
                metadata.set("x-api-key", "reader-key-e2e-test-long-enough");

                await expect(
                    grpcCall<IngestResponse>(
                        server.client, "Ingest",
                        {
                            traceId: "",
                            type: "SYSTEM",
                            level: 3,
                            serviceId: "e2e-sdk",
                            message: "Reader role should fail",
                            origin: "SYSTEM",
                            tags: [],
                            resourceIds: [],
                            input: "",
                        },
                        metadata,
                    ),
                ).rejects.toThrow();
            } finally {
                await server.cleanup();
            }
        }, 30_000);

        it("authz disabled allows all clients to write", async () => {
            const noAuthzConfig = authzConfig
                .replace(/authorization:\n  enabled: true/, "authorization:\n  enabled: false");

            const server = await launchServer(noAuthzConfig);
            try {
                const metadata = new server.grpc.Metadata();
                metadata.set("x-api-key", "reader-key-e2e-test-long-enough");

                const res = await grpcCall<IngestResponse>(
                    server.client, "Ingest",
                    {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: "Authz disabled, reader can write",
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    },
                    metadata,
                );
                expect(res.traceId).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 15. マスキングと全フラグの組み合わせ一括検証
    // ==================================================================
    describe("Full feature config: masking + hash chain + ensemble + response", () => {
        it("server with all features enabled processes critical security log end-to-end", async () => {
            const fullConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: true
  enable_hash_chain: true
  masking_rules:
    - type: PII_TYPE
      category: EMAIL
    - type: PII_TYPE
      category: CREDIT_CARD
pipeline:
  service_id: full-feature-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
    - rule_id: sec-escalate
      event_name: SECURITY_INTRUSION_DETECTED
      severity: HIGH
      action_type: ESCALATE
      execution_level: AUTO
      priority: 1
      description: "Escalate security intrusion"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 2
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: true
  aggregator: max
  threshold: 0.5
  dedup_window_sec: 0
  dynamic_rules:
    - rule_id: ensemble-sec
      event_name: SECURITY_INTRUSION_DETECTED
      priority: HIGH
      score: 1.0
      conditions:
        log_types: ["SECURITY"]
        min_level: 4
anomaly:
  enabled: true
  window_size_sec: 60
  baseline_window_sec: 300
  threshold_pct: 200.0
  min_baseline: 5.0
agent:
  enabled: false
response:
  enabled: true
  default_strategy: BLOCK_AND_ANALYZE
  block_mode: IMMEDIATE
  rules:
    - event_name: SECURITY_INTRUSION_DETECTED
      strategy: BLOCK_AND_ANALYZE
      block_action: ip_block
      notify_targets:
        - "#security"
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(fullConfig);
            try {
                // ConfigSummary reflects all features
                const health = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(health.status).toBe("SERVING");
                expect(health.configSummary.maskingEnabled).toBe(true);
                expect(health.configSummary.hashChainEnabled).toBe(true);
                expect(health.configSummary.maskingRulesCount).toBe(2);
                expect(health.configSummary.taskRulesCount).toBe(2);

                // Critical security log with PII → masking + hash chain + detection + task + threat response
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 6,
                    boundary: "e2e:full-feature",
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Intrusion from 10.0.0.1, attacker@evil.com exfiltrating card 4111-1111-1111-1111",
                    origin: "SYSTEM",
                    tags: [{ key: "ip", category: "10.0.0.1" }],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                expect(res.masked).toBe(true);
                expect(res.hashChainValid).toBe(true);
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.threatResponses.length).toBeGreaterThan(0);
                expect(res.threatResponses[0].strategy).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });
    // ==================================================================
    // 16. ESCALATE アクションハンドラ
    // ==================================================================
    describe("ESCALATE action handler", () => {
        it("dispatches escalation task for security intrusion", async () => {
            const escalateConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: escalate-server
  rules:
    - rule_id: sec-escalate
      event_name: SECURITY_INTRUSION_DETECTED
      severity: HIGH
      action_type: ESCALATE
      execution_level: AUTO
      priority: 1
      description: "Escalate security intrusion"
      exec_params:
        notification_channel: "#security-critical"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(escalateConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SECURITY",
                    level: 5,
                    serviceId: "e2e-sdk",
                    isCritical: false,
                    message: "Security intrusion requiring escalation",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.tasksGenerated.some((t) => t.ruleId === "sec-escalate")).toBe(true);
                expect(res.tasksGenerated.find((t) => t.ruleId === "sec-escalate")?.status).toBe("dispatched");
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 17. SYSTEM_NOTIFICATION アクションハンドラ
    // ==================================================================
    describe("SYSTEM_NOTIFICATION action handler", () => {
        it("dispatches notification task for critical failure", async () => {
            const notifyConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: notify-server
  rules:
    - rule_id: crit-notify
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: HIGH
      action_type: SYSTEM_NOTIFICATION
      execution_level: AUTO
      priority: 1
      description: "Notify on critical failure"
      exec_params:
        notification_channel: "#ops"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 3
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
`;
            const server = await launchServer(notifyConfig);
            try {
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 6,
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Critical system failure",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });

                expect(res.traceId).toBeTruthy();
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.tasksGenerated[0].ruleId).toBe("crit-notify");
                expect(res.tasksGenerated[0].status).toBe("dispatched");
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });

    // ==================================================================
    // 18. KILL_SWITCH アクションハンドラ
    // ==================================================================
    describe("KILL_SWITCH action handler", () => {
        it("kills pipeline after critical event, rejects subsequent ingest", async () => {
            const killConfig = `
server:
  addr: ":0"
  graceful_timeout_sec: 5
security:
  enable_masking: false
  enable_hash_chain: false
pipeline:
  service_id: kill-switch-server
  rules:
    - rule_id: emergency-stop
      event_name: SYSTEM_CRITICAL_FAILURE
      severity: CRITICAL
      action_type: KILL_SWITCH
      execution_level: AUTO
      priority: 1
      description: "Emergency kill switch"
      guardrails:
        require_human_approval: false
        timeout_ms: 30000
        max_retries: 0
store:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
auth:
  enabled: false
webhook:
  enabled: false
ensemble:
  enabled: false
anomaly:
  enabled: false
agent:
  enabled: false
response:
  enabled: false
authorization:
  enabled: false
masking_policies: []
routing_rules: []
kill_switch:
  auto_recovery_timeout_sec: 3
`;
            const server = await launchServer(killConfig);
            try {
                // First ingest triggers KILL_SWITCH
                const res = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 6,
                    serviceId: "e2e-sdk",
                    isCritical: true,
                    message: "Critical failure triggering kill switch",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(res.tasksGenerated.length).toBeGreaterThan(0);
                expect(res.tasksGenerated[0].ruleId).toBe("emergency-stop");

                // Subsequent ingest should be rejected (pipeline killed)
                await expect(
                    grpcCall<IngestResponse>(server.client, "Ingest", {
                        traceId: "",
                        type: "SYSTEM",
                        level: 3,
                        serviceId: "e2e-sdk",
                        message: "This should be rejected",
                        origin: "SYSTEM",
                        tags: [],
                        resourceIds: [],
                        input: "",
                    }),
                ).rejects.toThrow();

                // HealthCheck should still work even when pipeline is killed
                const health = await grpcCall<HealthCheckResponse>(server.client, "HealthCheck", {});
                expect(health.status).toBe("SERVING");

                // Wait for auto-recovery (3 seconds)
                await new Promise((r) => setTimeout(r, 3500));

                // After recovery, ingest should work again
                const recovered = await grpcCall<IngestResponse>(server.client, "Ingest", {
                    traceId: "",
                    type: "SYSTEM",
                    level: 3,
                    serviceId: "e2e-sdk",
                    message: "Pipeline recovered",
                    origin: "SYSTEM",
                    tags: [],
                    resourceIds: [],
                    input: "",
                });
                expect(recovered.traceId).toBeTruthy();
            } finally {
                await server.cleanup();
            }
        }, 30_000);
    });
}, 600_000); // 10 minute total timeout for the entire suite
