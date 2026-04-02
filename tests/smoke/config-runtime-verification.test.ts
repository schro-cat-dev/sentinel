/**
 * Config Runtime Verification Tests
 *
 * ビルド済みSDKではなくソースから直接importするが、
 * 全configフィールドが実際のパイプラインに正しく反映されるかを
 * 実動作レベルで検証する。
 *
 * unit テストとの違い:
 * - mock を最小限に抑え、実際のコンポーネントを通す
 * - fetch のみ mock（ネットワーク依存を排除）
 * - config の各フィールドが「最終的な出力」に正しく反映されるかを検証
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    Sentinel,
    createDefaultConfig,
    parseConfigYaml,
    ConsoleTaskTransport,
    HttpWebhookTransport,
    createTaskTransportsFromConfig,
    ValidationError,
} from "../../src/index";
import type { SentinelConfig, TaskTransportConfig } from "../../src/configs/sentinel-config";
import type { GeneratedTask } from "../../src/types/task";

// =========================================================================
// Setup
// =========================================================================

const originalFetch = globalThis.fetch;
beforeEach(() => { Sentinel.reset(); });
afterEach(() => { Sentinel.reset(); globalThis.fetch = originalFetch; });

// =========================================================================
// Helpers
// =========================================================================

function baseConfig(overrides: Partial<SentinelConfig> = {}): SentinelConfig {
    return createDefaultConfig({
        projectName: "runtime-verify",
        serviceId: "rv-svc",
        environment: "test",
        security: { enableHashChain: false },
        taskRules: [{
            ruleId: "rv-rule",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "CRITICAL",
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "AUTO",
            priority: 1,
            description: "runtime verify",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 0 },
        }],
        ...overrides,
    });
}

/** 確実にイベント検知→タスク生成を発火させるログ */
const TRIGGER_LOG = { message: "runtime verify critical", level: 6 as const, isCritical: true };
/** 検知にマッチしないログ */
const SILENT_LOG = { message: "info", level: 1 as const };

/** タスクをキャプチャするユーティリティ transport */
function captureTransport() {
    const captured: GeneratedTask[] = [];
    const transport = {
        name: "capture",
        dispatch: vi.fn().mockImplementation(async (task: GeneratedTask) => {
            captured.push(structuredClone(task));
            return { transportName: "capture", success: true };
        }),
        close: vi.fn().mockResolvedValue(undefined),
    };
    return { captured, transport };
}

// =========================================================================
// A. ConsoleTaskTransport 実動作
// =========================================================================

describe("A. ConsoleTaskTransport runtime", () => {
    it("A-01 config type=console → console.info に正しい JSON 出力", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = baseConfig({
            taskTransportConfigs: [{ name: "rt-console", type: "console", enabled: true }],
        });
        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest(TRIGGER_LOG);

        expect(spy).toHaveBeenCalledTimes(1);
        const output = JSON.parse(spy.mock.calls[0][0] as string);
        expect(output.sentinel_task.taskId).toBeTruthy();
        expect(output.sentinel_task.ruleId).toBe("rv-rule");
        expect(output.sentinel_task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(output.sentinel_task.severity).toBe("CRITICAL");
        expect(output.sentinel_task.actionType).toBe("SYSTEM_NOTIFICATION");
        expect(output.sentinel_task.executionLevel).toBe("AUTO");
        expect(output.sentinel_task.priority).toBe(1);
        expect(output.sentinel_task.sourceLog.message).toBe("runtime verify critical");
        expect(output.sentinel_task.sourceLog.level).toBe(6);
        expect(output.sentinel_task.sourceLog.traceId).toBeTruthy();
        expect(output.sentinel_task.createdAt).toBeTruthy();
        expect(output.timestamp).toBeTruthy();
        spy.mockRestore();
    });

    it("A-02 close 後の dispatch は success=false を返す", async () => {
        const transport = new ConsoleTaskTransport("rt");
        await transport.close();
        const result = await transport.dispatch({} as GeneratedTask);
        expect(result.success).toBe(false);
        expect(result.error).toContain("closed");
    });
});

// =========================================================================
// B. HttpWebhookTransport 実動作
// =========================================================================

describe("B. HttpWebhookTransport runtime", () => {
    it("B-01 config type=http_webhook → fetch に正しい request body", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        const config = baseConfig({
            taskTransportConfigs: [{
                name: "rt-webhook",
                type: "http_webhook",
                endpoint: "https://hooks.example.com/sentinel",
                headers: { "X-Api-Key": "secret123" },
            } as TaskTransportConfig],
        });
        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest(TRIGGER_LOG);

        expect(fetchSpy).toHaveBeenCalledTimes(1);
        const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("https://hooks.example.com/sentinel");
        expect(opts.method).toBe("POST");
        const headers = opts.headers as Record<string, string>;
        expect(headers["Content-Type"]).toBe("application/json");
        expect(headers["X-Api-Key"]).toBe("secret123");

        const body = JSON.parse(opts.body as string) as GeneratedTask;
        expect(body.taskId).toBeTruthy();
        expect(body.ruleId).toBe("rv-rule");
        expect(body.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(body.sourceLog.message).toBe("runtime verify critical");
    });

    it("B-02 method=PUT config → fetch method=PUT", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        const config = baseConfig({
            taskTransportConfigs: [{
                name: "rt-put", type: "http_webhook",
                endpoint: "https://hooks.example.com/put", method: "PUT",
            } as TaskTransportConfig],
        });
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe("PUT");
    });

    it("B-03 SSRF endpoint → initialize で例外", () => {
        expect(() => Sentinel.initialize(baseConfig({
            taskTransportConfigs: [{ name: "bad", type: "http_webhook", endpoint: "https://127.0.0.1/h" } as TaskTransportConfig],
        }))).toThrow();
    });

    it("B-04 HTTP → initialize で例外 (allowInsecure なし)", () => {
        expect(() => Sentinel.initialize(baseConfig({
            taskTransportConfigs: [{ name: "http", type: "http_webhook", endpoint: "http://example.com/h" } as TaskTransportConfig],
        }))).toThrow("HTTPS");
    });

    it("B-05 allow_insecure=true → HTTP localhost 許可", () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        expect(() => Sentinel.initialize(baseConfig({
            taskTransportConfigs: [{
                name: "dev", type: "http_webhook",
                endpoint: "http://localhost:3000/h", allow_insecure: true,
            } as TaskTransportConfig],
        }))).not.toThrow();
    });

    it("B-06 close 後 fetch 呼ばれない", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const transport = new HttpWebhookTransport({ endpoint: "https://example.com/h" });
        await transport.close();
        const result = await transport.dispatch({} as GeneratedTask);
        expect(result.success).toBe(false);
        expect(fetchSpy).not.toHaveBeenCalled();
    });
});

// =========================================================================
// C. Transport Factory 実動作
// =========================================================================

describe("C. createTaskTransportsFromConfig runtime", () => {
    it("C-01 mixed types: http_webhook + console + custom → 2件生成", () => {
        const transports = createTaskTransportsFromConfig([
            { name: "w", type: "http_webhook", endpoint: "https://example.com/h" } as TaskTransportConfig,
            { name: "c", type: "console" } as TaskTransportConfig,
            { name: "u", type: "custom" } as TaskTransportConfig,
        ]);
        expect(transports).toHaveLength(2);
        expect(transports[0]).toBeInstanceOf(HttpWebhookTransport);
        expect(transports[1]).toBeInstanceOf(ConsoleTaskTransport);
    });

    it("C-02 enabled=false → インスタンス生成しない", () => {
        const transports = createTaskTransportsFromConfig([
            { name: "off", type: "console", enabled: false } as TaskTransportConfig,
        ]);
        expect(transports).toHaveLength(0);
    });

    it("C-03 SSRF endpoint + enabled=false → throw しない", () => {
        expect(() => createTaskTransportsFromConfig([
            { name: "ssrf-off", type: "http_webhook", endpoint: "https://10.0.0.1/h", enabled: false } as TaskTransportConfig,
        ])).not.toThrow();
    });

    it("C-04 SSRF endpoint + enabled=true → throw する", () => {
        expect(() => createTaskTransportsFromConfig([
            { name: "ssrf-on", type: "http_webhook", endpoint: "https://10.0.0.1/h", enabled: true } as TaskTransportConfig,
        ])).toThrow();
    });
});

// =========================================================================
// D. masking × transport 実反映
// =========================================================================

describe("D. masking reflected in transport payload", () => {
    it("D-01 masking.enabled=true: transport が受け取る message はマスク済み", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: ["traceId"],
            },
        });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest({ ...TRIGGER_LOG, message: "contact admin@corp.com for help" });

        expect(captured).toHaveLength(1);
        expect(captured[0].sourceLog.message).not.toContain("admin@corp.com");
        expect(captured[0].sourceLog.message).toContain("[MASKED_EMAIL]");
    });

    it("D-02 masking.enabled=false: transport が受け取る message は原文", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({ masking: { enabled: false, rules: [], preserveFields: [] } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest({ ...TRIGGER_LOG, message: "contact admin@corp.com for help" });

        expect(captured).toHaveLength(1);
        expect(captured[0].sourceLog.message).toContain("admin@corp.com");
    });

    it("D-03 masking + credit card: transport payload にカード番号なし", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "CREDIT_CARD" }],
                preserveFields: ["traceId"],
            },
        });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest({ ...TRIGGER_LOG, message: "card 4111111111111111 used" });

        expect(captured).toHaveLength(1);
        expect(captured[0].sourceLog.message).not.toContain("4111111111111111");
    });
});

// =========================================================================
// E. security.enableHashChain × transport
// =========================================================================

describe("E. hashChain reflected in result", () => {
    it("E-01 hashChain=true: result.hashChainValid=true + transport dispatches", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({ security: { enableHashChain: true } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(r.hashChainValid).toBe(true);
        expect(captured).toHaveLength(1);
    });

    it("E-02 hashChain=false: result.hashChainValid=false + transport dispatches", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({ security: { enableHashChain: false } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(r.hashChainValid).toBe(false);
        expect(captured).toHaveLength(1);
    });

    it("E-03 hashChain=true + 連続 ingest: chain 維持 + 毎回 transport dispatch", async () => {
        const { captured, transport } = captureTransport();
        const config = baseConfig({ security: { enableHashChain: true } });
        Sentinel.initialize(config, { taskTransports: [transport] });

        const r1 = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        const r2 = await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(r1.hashChainValid).toBe(true);
        expect(r2.hashChainValid).toBe(true);
        expect(r1.traceId).not.toBe(r2.traceId);
        expect(captured).toHaveLength(2);
    });
});

// =========================================================================
// F. execution level × transport 実動作
// =========================================================================

describe("F. execution level reflected in transport dispatch", () => {
    function configWithLevel(level: string, approval = false) {
        return baseConfig({
            taskRules: [{
                ruleId: "rv-rule", eventName: "SYSTEM_CRITICAL_FAILURE", severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION", executionLevel: level as "AUTO",
                priority: 1, description: "test", executionParams: {},
                guardrails: { requireHumanApproval: approval, timeoutMs: 30000, maxRetries: 0 },
            }],
        });
    }

    it("F-01 AUTO: transport receives task", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(configWithLevel("AUTO"), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("dispatched");
        expect(captured).toHaveLength(1);
    });

    it("F-02 SEMI_AUTO (no handler): AUTO fallback → transport receives", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(configWithLevel("SEMI_AUTO"), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("dispatched");
        expect(captured).toHaveLength(1);
    });

    it("F-03 SEMI_AUTO + confirm=true: transport receives", async () => {
        const { captured, transport } = captureTransport();
        const sentinel = Sentinel.initialize(configWithLevel("SEMI_AUTO"), { taskTransports: [transport] });
        sentinel.onTaskConfirm(() => true);
        const r = await sentinel.ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("dispatched");
        expect(captured).toHaveLength(1);
    });

    it("F-04 SEMI_AUTO + confirm=false: transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        const sentinel = Sentinel.initialize(configWithLevel("SEMI_AUTO"), { taskTransports: [transport] });
        sentinel.onTaskConfirm(() => false);
        const r = await sentinel.ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("blocked_approval");
        expect(captured).toHaveLength(0);
    });

    it("F-05 MANUAL: transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(configWithLevel("MANUAL"), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("blocked_approval");
        expect(captured).toHaveLength(0);
    });

    it("F-06 MONITOR: transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(configWithLevel("MONITOR"), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("skipped");
        expect(captured).toHaveLength(0);
    });

    it("F-07 requireHumanApproval=true: transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(configWithLevel("AUTO", true), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("blocked_approval");
        expect(captured).toHaveLength(0);
    });
});

// =========================================================================
// G. callbacks × transport 実動作
// =========================================================================

describe("G. callbacks firing with transport", () => {
    it("G-01 onTaskGenerated fires before transport dispatch", async () => {
        const order: string[] = [];
        const { transport } = captureTransport();
        transport.dispatch = vi.fn().mockImplementation(async () => { order.push("transport"); return { transportName: "c", success: true }; });
        const config = baseConfig({ onTaskGenerated: () => { order.push("onTaskGenerated"); } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(order[0]).toBe("onTaskGenerated");
        expect(order[1]).toBe("transport");
    });

    it("G-02 onTaskDispatched receives dispatched result", async () => {
        const onTaskDispatched = vi.fn();
        const { transport } = captureTransport();
        const config = baseConfig({ onTaskDispatched });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onTaskDispatched).toHaveBeenCalledTimes(1);
        expect(onTaskDispatched.mock.calls[0][0].status).toBe("dispatched");
        expect(onTaskDispatched.mock.calls[0][0].taskId).toBeTruthy();
    });

    it("G-03 onTaskDispatched receives failed result on transport error", async () => {
        const onTaskDispatched = vi.fn();
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });
        const config = baseConfig({
            onTaskDispatched,
            taskTransportConfigs: [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" } as TaskTransportConfig],
        });
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onTaskDispatched).toHaveBeenCalledTimes(1);
        expect(onTaskDispatched.mock.calls[0][0].status).toBe("failed");
        expect(onTaskDispatched.mock.calls[0][0].error).toContain("500");
    });

    it("G-04 onTaskGenerated throws → transport still dispatches", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const { captured, transport } = captureTransport();
        const config = baseConfig({
            onTaskGenerated: () => { throw new Error("callback boom"); },
        });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(captured).toHaveLength(1);
        stderrSpy.mockRestore();
    });

    it("G-05 onError receives context on callback failure (not transport failure)", async () => {
        const onError = vi.fn();
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const config = baseConfig({
            onError,
            onTaskGenerated: () => { throw new Error("cb fail"); },
        });
        const { transport } = captureTransport();
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onError).toHaveBeenCalled();
        expect(onError.mock.calls[0][0].message).toBe("cb fail");
        stderrSpy.mockRestore();
    });
});

// =========================================================================
// H. metrics × transport 実動作
// =========================================================================

describe("H. metrics hooks with transport", () => {
    it("H-01 onTaskDispatch fires with dispatched result", async () => {
        const onTaskDispatch = vi.fn();
        const { transport } = captureTransport();
        const config = baseConfig({ metrics: { onTaskDispatch } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onTaskDispatch).toHaveBeenCalledTimes(1);
        expect(onTaskDispatch.mock.calls[0][0].status).toBe("dispatched");
    });

    it("H-02 onTaskDispatch fires with failed result", async () => {
        const onTaskDispatch = vi.fn();
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });
        const config = baseConfig({
            metrics: { onTaskDispatch },
            taskTransportConfigs: [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" } as TaskTransportConfig],
        });
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onTaskDispatch).toHaveBeenCalledTimes(1);
        expect(onTaskDispatch.mock.calls[0][0].status).toBe("failed");
    });

    it("H-03 onIngest fires alongside transport dispatch", async () => {
        const onIngest = vi.fn();
        const { captured, transport } = captureTransport();
        const config = baseConfig({ metrics: { onIngest } });
        Sentinel.initialize(config, { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(onIngest).toHaveBeenCalledTimes(1);
        expect(captured).toHaveLength(1);
    });
});

// =========================================================================
// I. validationLimits × transport
// =========================================================================

describe("I. validationLimits gate before transport", () => {
    it("I-01 oversized message → ValidationError, transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });

        await expect(Sentinel.getInstance().ingest({ message: "x".repeat(70000), level: 6, isCritical: true }))
            .rejects.toThrow(ValidationError);
        expect(captured).toHaveLength(0);
    });

    it("I-02 empty message → ValidationError, transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });

        await expect(Sentinel.getInstance().ingest({ message: "", level: 6 }))
            .rejects.toThrow(ValidationError);
        expect(captured).toHaveLength(0);
    });

    it("I-03 valid message → transport dispatches normally", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });

        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(captured).toHaveLength(1);
    });
});

// =========================================================================
// J. lifecycle 全パターン
// =========================================================================

describe("J. lifecycle: init → dispatch → shutdown → re-init", () => {
    it("J-01 full cycle: init → dispatch → shutdown → re-init → dispatch", async () => {
        const { captured: c1, transport: t1 } = captureTransport();
        let sentinel = Sentinel.initialize(baseConfig(), { taskTransports: [t1] });
        await sentinel.ingest(TRIGGER_LOG);
        expect(c1).toHaveLength(1);

        await sentinel.shutdown();

        const { captured: c2, transport: t2 } = captureTransport();
        sentinel = Sentinel.initialize(baseConfig(), { taskTransports: [t2] });
        await sentinel.ingest(TRIGGER_LOG);
        expect(c2).toHaveLength(1);
    });

    it("J-02 ingest after shutdown → Error", async () => {
        const sentinel = Sentinel.initialize(baseConfig());
        await sentinel.shutdown();
        await expect(sentinel.ingest(TRIGGER_LOG)).rejects.toThrow("shutdown");
    });

    it("J-03 double shutdown → idempotent", async () => {
        const { transport } = captureTransport();
        const sentinel = Sentinel.initialize(baseConfig(), { taskTransports: [transport] });
        await sentinel.shutdown();
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
        expect(transport.close).toHaveBeenCalledTimes(1);
    });

    it("J-04 reset → re-init works", async () => {
        Sentinel.initialize(baseConfig());
        Sentinel.reset();

        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(captured).toHaveLength(1);
    });

    it("J-05 shutdown calls transport.close()", async () => {
        const { transport } = captureTransport();
        const sentinel = Sentinel.initialize(baseConfig(), { taskTransports: [transport] });
        await sentinel.shutdown();
        expect(transport.close).toHaveBeenCalledTimes(1);
    });

    it("J-06 multiple ingest → transport called each time", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });
        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(captured).toHaveLength(3);
        // 各タスクの traceId は異なる
        const ids = new Set(captured.map((t) => t.sourceLog.traceId));
        expect(ids.size).toBe(3);
    });
});

// =========================================================================
// K. dispatch 結果 × transport 実動作
// =========================================================================

describe("K. HTTP response → TaskResult propagation", () => {
    afterEach(() => { globalThis.fetch = originalFetch; });

    const webhookConfig = () => baseConfig({
        taskTransportConfigs: [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" } as TaskTransportConfig],
    });

    for (const [status, ok, expectedStatus] of [
        [200, true, "dispatched"],
        [201, true, "dispatched"],
        [400, false, "failed"],
        [401, false, "failed"],
        [403, false, "failed"],
        [404, false, "failed"],
        [429, false, "failed"],
        [500, false, "failed"],
        [502, false, "failed"],
        [503, false, "failed"],
    ] as const) {
        it(`K-XX HTTP ${status} → task ${expectedStatus}`, async () => {
            globalThis.fetch = vi.fn().mockResolvedValue({ ok, status });
            Sentinel.initialize(webhookConfig());
            const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
            expect(r.tasksGenerated[0].status).toBe(expectedStatus);
            if (!ok) {
                expect(r.tasksGenerated[0].error).toContain(String(status));
            }
        });
    }

    it("K-XX ECONNREFUSED → task failed", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
        Sentinel.initialize(webhookConfig());
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("ECONNREFUSED");
    });

    it("K-XX ETIMEDOUT → task failed", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("ETIMEDOUT"));
        Sentinel.initialize(webhookConfig());
        const r = await Sentinel.getInstance().ingest(TRIGGER_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("ETIMEDOUT");
    });
});

// =========================================================================
// L. 複合パターン
// =========================================================================

describe("L. compound patterns (multi-config interaction)", () => {
    it("L-01 masking + hashChain + console transport: all reflected", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = baseConfig({
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: ["traceId"] },
            security: { enableHashChain: true },
            taskTransportConfigs: [{ name: "c", type: "console", enabled: true }],
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest({ ...TRIGGER_LOG, message: "user@test.com critical" });

        expect(r.hashChainValid).toBe(true);
        expect(r.masked).toBe(true);
        expect(r.tasksGenerated[0].status).toBe("dispatched");

        const output = JSON.parse(spy.mock.calls[0][0] as string);
        expect(output.sentinel_task.sourceLog.message).not.toContain("user@test.com");
        spy.mockRestore();
    });

    it("L-02 masking + webhook + metrics: all fire correctly", async () => {
        const onTaskDispatch = vi.fn();
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        const config = baseConfig({
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "PHONE" }], preserveFields: ["traceId"] },
            metrics: { onTaskDispatch },
            taskTransportConfigs: [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" } as TaskTransportConfig],
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest({ ...TRIGGER_LOG, message: "call 090-1234-5678 now" });

        // masking
        expect(r.masked).toBe(true);
        const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
        expect(body.sourceLog.message).not.toContain("090-1234-5678");

        // metrics
        expect(onTaskDispatch).toHaveBeenCalledTimes(1);
        expect(onTaskDispatch.mock.calls[0][0].status).toBe("dispatched");
    });

    it("L-03 user transport + config console + handler: all 3 execute", async () => {
        const handler = vi.fn();
        const { captured: userCaptured, transport: userTransport } = captureTransport();
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = baseConfig({
            taskTransportConfigs: [{ name: "c", type: "console", enabled: true }],
        });
        const sentinel = Sentinel.initialize(config, { taskTransports: [userTransport] });
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        await sentinel.ingest(TRIGGER_LOG);

        expect(handler).toHaveBeenCalledTimes(1);
        expect(userCaptured).toHaveLength(1);
        expect(spy).toHaveBeenCalledTimes(1);
        spy.mockRestore();
    });

    it("L-04 YAML config → factory → console + disabled webhook: only console dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const fetchSpy = vi.fn();
        globalThis.fetch = fetchSpy;

        const config = baseConfig({
            taskTransportConfigs: [
                { name: "c", type: "console", enabled: true },
                { name: "w", type: "http_webhook", endpoint: "https://example.com/h", enabled: false },
            ] as TaskTransportConfig[],
        });
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(TRIGGER_LOG);

        expect(spy).toHaveBeenCalled();
        expect(fetchSpy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("L-05 silent log (no detection) + transport: transport NOT called", async () => {
        const { captured, transport } = captureTransport();
        Sentinel.initialize(baseConfig(), { taskTransports: [transport] });
        const r = await Sentinel.getInstance().ingest(SILENT_LOG);

        expect(r.tasksGenerated).toHaveLength(0);
        expect(captured).toHaveLength(0);
    });
});
