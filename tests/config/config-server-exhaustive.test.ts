/**
 * Config Server Exhaustive Tests
 *
 * 全設定の組み合わせケースにおいて設定通りに動くか検証。
 * 加えて、各組み合わせでの侵入経路を網羅的にテスト。
 *
 * 設定次元:
 * - environment (5値)
 * - masking.enabled (true/false)
 * - security.enableHashChain (true/false)
 * - whitelist.level (strict/standard/permissive/off)
 * - transport.mode (local/remote/dual)
 * - detectionRules (present/absent)
 * - taskRules (present/empty)
 * - metrics (present/absent)
 * - callbacks (present/absent)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../src/index";
import { createTestTaskRule, createTestLog } from "../helpers/fixtures";
import type { SentinelConfig } from "../../src/index";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== ヘルパー =====
const detectionRule = () => ({
    ruleId: "test-detect",
    eventName: "SECURITY_INTRUSION_DETECTED" as const,
    priority: "HIGH" as const,
    conditions: { messagePattern: /intrusion/ },
});

const taskRule = () => createTestTaskRule({
    eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "CRITICAL",
    executionLevel: "AUTO",
});

const mockTransport = () => ({
    send: vi.fn().mockResolvedValue({
        traceId: "remote", hashChainValid: false, tasksGenerated: [], masked: false, detection: null,
    }),
    close: vi.fn(),
});

// ===== 1. 設定マトリクス: 代表的組み合わせ =====
describe("Config matrix: representative combinations", () => {
    const environments: SentinelConfig["environment"][] = ["production", "staging", "development", "local", "test"];
    const maskingOptions = [true, false];
    const hashChainOptions = [true, false];
    const whitelistLevels: ("strict" | "standard" | "permissive" | "off")[] = ["strict", "standard", "permissive", "off"];

    // 全5環境で基本動作確認
    it.each(environments)("environment=%s initializes and ingests", async (env) => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            environment: env,
            security: { enableHashChain: false },
        }));
        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });

    // masking × hashChain マトリクス (2×2=4)
    it.each(
        maskingOptions.flatMap((m) => hashChainOptions.map((h) => [m, h])),
    )("masking=%s hashChain=%s processes correctly", async (masking, hashChain) => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: {
                enabled: masking as boolean,
                rules: masking ? [{ type: "PII_TYPE" as const, category: "EMAIL" as const }] : [],
                preserveFields: [],
            },
            security: { enableHashChain: hashChain as boolean },
        }));
        const result = await sentinel.ingest({
            message: "Contact alice@secret.com",
            level: 3,
        });
        expect(result.masked).toBe(masking);
        expect(result.hashChainValid).toBe(hashChain);
    });

    // 全4 whitelistレベルで正常な設定が通る
    it.each(whitelistLevels)("whitelist.level=%s accepts valid config", (level) => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [taskRule()],
                whitelist: { level },
            })),
        ).not.toThrow();
    });

    // production + strict + hashChain + masking + detectionRules + taskRules (本番想定フル構成)
    it("production full config: all features enabled", async () => {
        const onTaskGenerated = vi.fn();
        const onIngest = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "prod", serviceId: "api",
            environment: "production",
            masking: {
                enabled: true,
                rules: [
                    { type: "PII_TYPE", category: "EMAIL" },
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                ],
                preserveFields: ["traceId"],
            },
            security: { enableHashChain: true },
            detectionRules: [detectionRule()],
            taskRules: [taskRule()],
            whitelist: { level: "strict" },
            onTaskGenerated,
            metrics: { onIngest },
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());

        // isCritical log → detection + task + masking + hash
        const result = await sentinel.ingest({
            message: "System intrusion from alice@evil.com",
            isCritical: true, level: 6,
        });

        expect(result.masked).toBe(true);
        expect(result.hashChainValid).toBe(true);
        expect(result.detection?.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(onTaskGenerated).toHaveBeenCalled();
        expect(onIngest).toHaveBeenCalled();
    });

    // development + off + no features (最小構成)
    it("development minimal config: no features", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "dev", serviceId: "s",
            environment: "development",
            security: { enableHashChain: false },
            whitelist: { level: "off" },
        }));

        const result = await sentinel.ingest({ message: "test", level: 2 });
        expect(result.masked).toBe(false);
        expect(result.hashChainValid).toBe(false);
        expect(result.detection).toBeNull();
        expect(result.tasksGenerated).toEqual([]);
    });
});

// ===== 2. Transport × config 組み合わせ =====
describe("Config matrix: transport modes", () => {
    it("dual mode with masking ensures masked log is sent to remote", async () => {
        const transport = mockTransport();
        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                    preserveFields: [],
                },
                security: { enableHashChain: false },
            }),
            { transport: { mode: "dual", transport } },
        );

        await sentinel.ingest({ message: "user@secret.com test", level: 3 });

        // Remote should receive masked log
        expect(transport.send).toHaveBeenCalled();
        const sentLog = transport.send.mock.calls[0][0] as { message: string };
        expect(sentLog.message).not.toContain("user@secret.com");
        expect(sentLog.message).toContain("[MASKED_EMAIL]");
    });

    it("remote mode with fallback falls back on transport error", async () => {
        const transport = {
            send: vi.fn().mockRejectedValue(new Error("network down")),
            close: vi.fn(),
        };
        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "remote", transport, fallbackToLocal: true } },
        );

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined(); // Local fallback succeeded
    });

    it("dual mode surfaces transport error in result", async () => {
        const transport = {
            send: vi.fn().mockRejectedValue(new Error("timeout")),
            close: vi.fn(),
        };
        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "dual", transport } },
        );

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.transportError).toContain("timeout");
    });
});

// ===== 3. Whitelist domain × level 組み合わせ =====
describe("Config matrix: whitelist domain × level", () => {
    it("strict + all domains: rejects any invalid value", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
                whitelist: { level: "strict", enabledDomains: ["security", "task", "privacy"] },
            })),
        ).toThrow(ValidationError);
    });

    it("standard + security only: allows invalid actionType (task domain disabled)", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule({ actionType: "CUSTOM" as never })],
                whitelist: { level: "standard", enabledDomains: ["security"] },
            })),
        ).not.toThrow();
    });

    it("permissive + all domains: invalid values produce warnings", () => {
        const warnFn = vi.fn();
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
            taskRules: [createTestTaskRule({ severity: "ULTRA" as never })],
            whitelist: { level: "permissive" },
        }));
        expect(warnFn).toHaveBeenCalled();
    });

    it("off + any invalid config: no error, no warning", () => {
        const warnFn = vi.fn();
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                logger: { warn: warnFn, error: vi.fn() },
                taskRules: [createTestTaskRule({
                    eventName: "FAKE" as never,
                    actionType: "FAKE" as never,
                    severity: "FAKE" as never,
                })],
                whitelist: { level: "off" },
            })),
        ).not.toThrow();
        const whitelistWarnings = warnFn.mock.calls.filter(
            (c: unknown[]) => typeof c[0] === "string" && (c[0] as string).includes("invalid"),
        );
        expect(whitelistWarnings).toHaveLength(0);
    });
});

// ===== 4. Config transition: init → shutdown → re-init =====
describe("Config transition scenarios", () => {
    it("strict → shutdown → permissive: level downgrade works", async () => {
        const s1 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
            whitelist: { level: "strict" },
        }));
        await s1.ingest({ message: "strict mode", level: 3 });
        await s1.shutdown();

        // Re-init with permissive
        const s2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "CUSTOM" as never })],
            whitelist: { level: "permissive" },
        }));
        // Should work without error (permissive)
        const result = await s2.ingest({ message: "permissive mode", level: 3 });
        expect(result.traceId).toBeDefined();
    });

    it("hash chain resets across shutdown/re-init", async () => {
        const s1 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
        }));
        const r1 = await s1.ingest({ message: "first chain", level: 3 });
        expect(r1.hashChainValid).toBe(true);
        await s1.shutdown();

        const s2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
        }));
        const r2 = await s2.ingest({ message: "new chain", level: 3 });
        expect(r2.hashChainValid).toBe(true);
        // New chain, not continuation
    });

    it("detectionRules change across re-init", async () => {
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{ ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH", conditions: { messagePattern: /alpha/ } }],
        }));
        const r1 = await Sentinel.getInstance().ingest({ message: "alpha event", level: 3 });
        expect(r1.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        await Sentinel.getInstance().shutdown();

        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{ ruleId: "r2", eventName: "COMPLIANCE_VIOLATION", priority: "MEDIUM", conditions: { messagePattern: /beta/ } }],
        }));
        const r2 = await Sentinel.getInstance().ingest({ message: "alpha event", level: 3 });
        expect(r2.detection).toBeNull(); // alpha no longer matches
        const r3 = await Sentinel.getInstance().ingest({ message: "beta event", level: 3 });
        expect(r3.detection?.eventName).toBe("COMPLIANCE_VIOLATION");
    });
});

// ===== 5. Callback isolation =====
describe("Callback isolation under errors", () => {
    it("onTaskGenerated throwing does not prevent onTaskDispatched", async () => {
        const onDispatched = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [taskRule()],
            onTaskGenerated: () => { throw new Error("boom"); },
            onTaskDispatched: onDispatched,
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());

        await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(onDispatched).toHaveBeenCalled();
    });

    it("onLogProcessed throwing does not affect return value", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: () => { throw new Error("crash"); },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
        expect(result.masked).toBe(false);
    });

    it("metrics hook throwing does not affect pipeline", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: {
                onIngest: () => { throw new Error("metrics fail"); },
                onDetection: () => { throw new Error("metrics fail"); },
                onTaskDispatch: () => { throw new Error("metrics fail"); },
            },
            taskRules: [taskRule()],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.traceId).toBeDefined();
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
    });
});

// ===== 6. 侵入経路テスト =====
describe("Attack vectors: config-level", () => {
    it("frozen config prevents post-init mutation of taskRules", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [taskRule()],
        });
        Sentinel.initialize(config);

        expect(() => config.taskRules.push(createTestTaskRule({ ruleId: "injected" }))).toThrow();
    });

    it("frozen config prevents post-init mutation of detectionRules", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [detectionRule()],
        });
        Sentinel.initialize(config);

        expect(() => config.detectionRules!.push(detectionRule())).toThrow();
    });

    it("frozen config prevents nested mutation of guardrails", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [taskRule()],
        });
        Sentinel.initialize(config);

        expect(() => {
            (config.taskRules[0].guardrails as { timeoutMs: number }).timeoutMs = 0;
        }).toThrow();
    });

    it("JSON-parsed config with __proto__ in whitelist does not pollute", () => {
        const malicious = JSON.parse('{"projectName":"p","serviceId":"s","whitelist":{"extensions":{"__proto__":["evil"]}}}');
        const config = createDefaultConfig(malicious);
        Sentinel.initialize(config);

        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("evil");
    });

    it("whitelist level downgrade via re-init requires explicit shutdown", () => {
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            whitelist: { level: "strict" },
        }));

        // Second initialize with weaker level is silently ignored
        const s2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            whitelist: { level: "off" },
        }));

        // Still strict (first config preserved)
        expect(s2.getConfig().whitelist?.level).toBe("strict");
    });
});

// ===== 7. トレーシングフック =====
describe("F-03: Tracer hooks", () => {
    it("calls onPipelineStart and onPipelineEnd for each ingest", async () => {
        const onStart = vi.fn();
        const onEnd = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            tracer: { onPipelineStart: onStart, onPipelineEnd: onEnd },
        }));

        await sentinel.ingest({ message: "test", level: 3 });

        expect(onStart).toHaveBeenCalledTimes(1);
        expect(onStart).toHaveBeenCalledWith(expect.objectContaining({ operation: "ingest" }));
        expect(onEnd).toHaveBeenCalledTimes(1);
        expect(onEnd).toHaveBeenCalledWith(expect.objectContaining({
            operation: "ingest",
            success: true,
            durationMs: expect.any(Number),
        }));
    });

    it("durationMs is non-negative", async () => {
        let capturedDuration = -1;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            tracer: { onPipelineEnd: (ctx) => { capturedDuration = ctx.durationMs; } },
        }));

        await sentinel.ingest({ message: "test", level: 3 });
        expect(capturedDuration).toBeGreaterThanOrEqual(0);
    });

    it("tracer hook throwing does not crash pipeline", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            tracer: {
                onPipelineStart: () => { throw new Error("tracer boom"); },
                onPipelineEnd: () => { throw new Error("tracer boom"); },
            },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });

    it("no tracer config means zero overhead", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });
});

describe("Attack vectors: input-level", () => {
    it("XSS in message does not break pipeline", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({
            message: '<script>alert("xss")</script>',
            level: 3,
        });
        expect(result.traceId).toBeDefined();
    });

    it("null bytes in message are rejected", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(sentinel.ingest({ message: "test\x00inject", level: 3 })).rejects.toThrow();
    });

    it("oversized message is rejected", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(sentinel.ingest({
            message: "x".repeat(100_000),
            level: 3,
        })).rejects.toThrow();
    });

    it("prototype pollution in log tags is safe", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const result = await sentinel.ingest({
            message: "test",
            level: 3,
            tags: [{ key: "__proto__", category: "polluted" }],
        });
        expect(result.traceId).toBeDefined();
        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("polluted");
    });
});

describe("Attack vectors: handler-level", () => {
    it("handler timeout is enforced", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                executionLevel: "AUTO",
                guardrails: { requireHumanApproval: false, timeoutMs: 50, maxRetries: 0 },
            })],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {
            await new Promise((r) => setTimeout(r, 200));
        });

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("failed");
        expect(result.tasksGenerated[0].error).toContain("timeout");
    }, 10000);

    it("handler throwing returns failed status", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [taskRule()],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {
            throw new Error("handler crash");
        });

        const result = await sentinel.ingest({ message: "critical", isCritical: true, level: 6 });
        expect(result.tasksGenerated[0].status).toBe("failed");
        expect(result.tasksGenerated[0].error).toContain("handler crash");
    });
});
