/**
 * YAML Config → Transport → Dispatch 一貫テスト
 *
 * YAML文字列の解析 → SentinelConfig生成 → Sentinel初期化 → トランスポート自動生成
 * → ログ投入 → イベント検知 → タスク生成 → トランスポートdispatch
 * という全パイプラインを一気通貫で検証する。
 *
 * 各ステージの unit テストは個別ファイルにある。
 * このファイルは「config の設定が実際の動作に正しく反映されるか」を検証する。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseConfigYaml } from "../../src/configs/config-loader";
import { Sentinel } from "../../src/index";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// =========================================================================
// YAML ヘルパー（yaml パッケージ不要: yamlParser DI を使用）
// =========================================================================

function parseWithTransports(transportConfigs: Record<string, unknown>[], extraConfig: Record<string, unknown> = {}) {
    return parseConfigYaml("", {
        yamlParser: () => ({
            project_name: "yaml-integration-test",
            service_id: "test-svc",
            environment: "test",
            task_rules: [{
                rule_id: "rule-yaml-test",
                event_name: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                action_type: "SYSTEM_NOTIFICATION",
                execution_level: "AUTO",
                priority: 1,
                description: "YAML integration test rule",
                guardrails: { require_human_approval: false, timeout_ms: 30000, max_retries: 0 },
            }],
            task_transports: transportConfigs,
            ...extraConfig,
        }),
    });
}

// =========================================================================
// 正常系: YAML → console transport → dispatch
// =========================================================================

describe("YAML → console transport → dispatch pipeline", () => {
    it("YAML config with type=console creates transport and dispatches on event", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "yaml-console", type: "console" },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "YAML console test", level: 6, isCritical: true });

        // フルパイプライン検証: YAML → config → factory → ConsoleTaskTransport → dispatch → console.info
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(infoSpy).toHaveBeenCalled();

        const output = JSON.parse(infoSpy.mock.calls[0][0] as string);
        expect(output.sentinel_task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(output.sentinel_task.sourceLog.message).toBe("YAML console test");
        expect(output.timestamp).toBeDefined();

        infoSpy.mockRestore();
    });
});

// =========================================================================
// 正常系: YAML → http_webhook transport → dispatch (fetch mock)
// =========================================================================

describe("YAML → http_webhook transport → dispatch pipeline", () => {
    const originalFetch = globalThis.fetch;
    let fetchSpy: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it("YAML config with type=http_webhook creates transport and dispatches via fetch", async () => {
        const config = parseWithTransports([
            { name: "yaml-webhook", type: "http_webhook", endpoint: "https://hooks.example.com/sentinel" },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "YAML webhook test", level: 6, isCritical: true });

        // フルパイプライン: YAML → config → factory → HttpWebhookTransport → dispatch → fetch
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(fetchSpy).toHaveBeenCalled();

        const [url, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("https://hooks.example.com/sentinel");
        expect(options.method).toBe("POST");

        const body = JSON.parse(options.body as string);
        expect(body.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(body.sourceLog.message).toBe("YAML webhook test");
    });

    it("YAML config with custom headers are passed to fetch", async () => {
        const config = parseWithTransports([{
            name: "yaml-webhook-headers",
            type: "http_webhook",
            endpoint: "https://hooks.example.com/sentinel",
            headers: { Authorization: "Bearer yaml-token-123", "X-Source": "sentinel" },
        }]);

        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest({ message: "header test", level: 6, isCritical: true });

        const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        const headers = options.headers as Record<string, string>;
        expect(headers.Authorization).toBe("Bearer yaml-token-123");
        expect(headers["X-Source"]).toBe("sentinel");
        expect(headers["Content-Type"]).toBe("application/json");
    });

    it("YAML config with method=PUT is respected", async () => {
        const config = parseWithTransports([{
            name: "yaml-put",
            type: "http_webhook",
            endpoint: "https://hooks.example.com/sentinel",
            method: "PUT",
        }]);

        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest({ message: "PUT test", level: 6, isCritical: true });

        const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(options.method).toBe("PUT");
    });
});

// =========================================================================
// 正常系: 複数トランスポートの組み合わせ
// =========================================================================

describe("YAML → multiple transports combination", () => {
    const originalFetch = globalThis.fetch;
    let fetchSpy: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it("http_webhook + console: both dispatch on same event", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "webhook", type: "http_webhook", endpoint: "https://hooks.example.com/hook" },
            { name: "debug", type: "console" },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "multi transport", level: 6, isCritical: true });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // 両方のトランスポートが呼ばれる
        expect(fetchSpy).toHaveBeenCalled();
        expect(infoSpy).toHaveBeenCalled();

        infoSpy.mockRestore();
    });

    it("enabled + disabled mix: only enabled transports dispatch", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "active-console", type: "console", enabled: true },
            { name: "disabled-webhook", type: "http_webhook", endpoint: "https://hooks.example.com/hook", enabled: false },
            { name: "disabled-console", type: "console", enabled: false },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "enabled mix", level: 6, isCritical: true });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // active-console のみ dispatch される
        expect(infoSpy).toHaveBeenCalledTimes(result.tasksGenerated.length);
        // disabled-webhook は fetch されない
        expect(fetchSpy).not.toHaveBeenCalled();

        infoSpy.mockRestore();
    });

    it("type=custom is skipped by factory, user-injected transport works alongside", async () => {
        const userDispatch = vi.fn().mockResolvedValue({ transportName: "user-custom", success: true });
        const userTransport = { name: "user-custom", dispatch: userDispatch };
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "custom-skip", type: "custom" },
            { name: "auto-console", type: "console" },
        ]);

        const sentinel = Sentinel.initialize(config, { taskTransports: [userTransport] });
        const result = await sentinel.ingest({ message: "custom+user", level: 6, isCritical: true });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // user-injected + config-based console の両方が dispatch
        expect(userDispatch).toHaveBeenCalled();
        expect(infoSpy).toHaveBeenCalled();

        infoSpy.mockRestore();
    });
});

// =========================================================================
// 異常系: config バリデーションエラー
// =========================================================================

describe("YAML → transport config validation errors", () => {
    it("http_webhook with SSRF endpoint prevents initialization", () => {
        expect(() => {
            const config = parseWithTransports([
                { name: "ssrf", type: "http_webhook", endpoint: "https://192.168.1.1/hook" },
            ]);
            Sentinel.initialize(config);
        }).toThrow();
    });

    it("http_webhook without endpoint fails at YAML parsing stage", () => {
        expect(() => {
            parseWithTransports([
                { name: "no-endpoint", type: "http_webhook" },
            ]);
        }).toThrow("endpoint");
    });

    it("unknown type fails at YAML parsing stage", () => {
        expect(() => {
            parseWithTransports([
                { name: "bad-type", type: "kafka" },
            ] as Record<string, unknown>[]);
        }).toThrow("type");
    });

    it("invalid method fails at YAML parsing stage", () => {
        expect(() => {
            parseWithTransports([
                { name: "bad-method", type: "http_webhook", endpoint: "https://example.com", method: "DELETE" },
            ]);
        }).toThrow("method");
    });
});

// =========================================================================
// 異常系: dispatch エラーの伝播
// =========================================================================

describe("YAML → transport dispatch error propagation", () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it("http_webhook fetch failure results in task failed status", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });

        const config = parseWithTransports([
            { name: "failing-hook", type: "http_webhook", endpoint: "https://hooks.example.com/hook" },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "dispatch error test", level: 6, isCritical: true });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // transport の dispatch が success=false → TaskResult.status が failed
        const failedTasks = result.tasksGenerated.filter((t) => t.status === "failed");
        expect(failedTasks.length).toBeGreaterThan(0);
        expect(failedTasks[0].error).toContain("503");
    });

    it("http_webhook network error results in task failed status", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));

        const config = parseWithTransports([
            { name: "network-fail", type: "http_webhook", endpoint: "https://hooks.example.com/hook" },
        ]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "network error test", level: 6, isCritical: true });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        const failedTasks = result.tasksGenerated.filter((t) => t.status === "failed");
        expect(failedTasks.length).toBeGreaterThan(0);
        expect(failedTasks[0].error).toContain("ECONNREFUSED");
    });
});

// =========================================================================
// ライフサイクル: shutdown / close
// =========================================================================

describe("YAML → transport lifecycle (shutdown/close)", () => {
    it("shutdown closes config-created console transport without error", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "lifecycle-console", type: "console" },
        ]);

        const sentinel = Sentinel.initialize(config);
        // dispatch して動作確認
        await sentinel.ingest({ message: "before shutdown", level: 6, isCritical: true });
        expect(infoSpy).toHaveBeenCalled();

        // shutdown → close が呼ばれてもエラーにならない
        await expect(sentinel.shutdown()).resolves.toBeUndefined();

        infoSpy.mockRestore();
    });

    it("shutdown closes config-created http_webhook transport", async () => {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

        const config = parseWithTransports([
            { name: "lifecycle-webhook", type: "http_webhook", endpoint: "https://hooks.example.com/hook" },
        ]);

        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest({ message: "before shutdown", level: 6, isCritical: true });

        // shutdown → AbortController.abort() が呼ばれてもエラーにならない
        await expect(sentinel.shutdown()).resolves.toBeUndefined();

        globalThis.fetch = originalFetch;
    });

    it("all disabled transports: no transports to close on shutdown", async () => {
        const config = parseWithTransports([
            { name: "disabled-1", type: "console", enabled: false },
            { name: "disabled-2", type: "http_webhook", endpoint: "https://example.com", enabled: false },
        ]);

        const sentinel = Sentinel.initialize(config);
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
    });
});

// =========================================================================
// エッジケース
// =========================================================================

describe("YAML → transport edge cases", () => {
    it("empty task_transports array: no transports, pipeline still works", async () => {
        const config = parseWithTransports([]);

        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "no transports", level: 6, isCritical: true });

        expect(result.traceId).toBeDefined();
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        // タスクは生成されるが transport dispatch はない → status は dispatched (handler もないので noop)
    });

    it("detection rule does not match: transports are not called", async () => {
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

        const config = parseWithTransports([
            { name: "idle-console", type: "console" },
        ]);

        const sentinel = Sentinel.initialize(config);
        // level 1 では検知ルールにマッチしない
        const result = await sentinel.ingest({ message: "low level log", level: 1 });

        expect(result.tasksGenerated).toHaveLength(0);
        expect(infoSpy).not.toHaveBeenCalled();

        infoSpy.mockRestore();
    });
});
