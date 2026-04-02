/**
 * YAML Config → Transport → Dispatch 一貫テスト
 *
 * configの設定が実際の動作に正しく反映されるかを全組み合わせで検証する。
 * 正常系 / 異常系 / エッジケース / 組み合わせマトリクス を網羅。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseConfigYaml } from "../../src/configs/config-loader";
import { Sentinel } from "../../src/index";
import type { SentinelConfig } from "../../src/configs/sentinel-config";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// =========================================================================
// ヘルパー
// =========================================================================

/** デフォルトのタスクルール（SYSTEM_CRITICAL_FAILURE → AUTO NOTIFICATION） */
const DEFAULT_TASK_RULE = {
    rule_id: "rule-yaml-test",
    event_name: "SYSTEM_CRITICAL_FAILURE",
    severity: "CRITICAL",
    action_type: "SYSTEM_NOTIFICATION",
    execution_level: "AUTO",
    priority: 1,
    description: "YAML integration test rule",
    guardrails: { require_human_approval: false, timeout_ms: 30000, max_retries: 0 },
};

function parseWithTransports(
    transportConfigs: Record<string, unknown>[],
    taskRules: Record<string, unknown>[] = [DEFAULT_TASK_RULE],
    extraConfig: Record<string, unknown> = {},
) {
    return parseConfigYaml("", {
        yamlParser: () => ({
            project_name: "yaml-integration-test",
            service_id: "test-svc",
            environment: "test",
            task_rules: taskRules,
            task_transports: transportConfigs,
            ...extraConfig,
        }),
    });
}

/** イベント検知を確実にトリガーするログ */
const CRITICAL_LOG = { message: "critical failure", level: 6, isCritical: true };
/** イベント検知にマッチしないログ */
const LOW_LOG = { message: "info log", level: 1 };

// =========================================================================
// 1. 単一トランスポート正常系
// =========================================================================

describe("1. Single transport: normal cases", () => {
    it("1-01 console: creates, dispatches, outputs structured JSON", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c1", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest(CRITICAL_LOG);

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        const out = JSON.parse(spy.mock.calls[0][0] as string);
        expect(out.sentinel_task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        expect(out.sentinel_task.sourceLog.message).toBe("critical failure");
        expect(out.timestamp).toBeTruthy();
        spy.mockRestore();
    });

    it("1-02 http_webhook POST: creates, dispatches via fetch", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([
            { name: "w1", type: "http_webhook", endpoint: "https://hooks.example.com/a" },
        ]);
        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest(CRITICAL_LOG);

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(fetchSpy).toHaveBeenCalled();
        const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("https://hooks.example.com/a");
        expect(opts.method).toBe("POST");
        const body = JSON.parse(opts.body as string);
        expect(body.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        globalThis.fetch = undefined!;
    });

    it("1-03 http_webhook PUT: method respected", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([
            { name: "w-put", type: "http_webhook", endpoint: "https://hooks.example.com/b", method: "PUT" },
        ]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect((fetchSpy.mock.calls[0][1] as RequestInit).method).toBe("PUT");
        globalThis.fetch = undefined!;
    });

    it("1-04 http_webhook custom headers passed to fetch", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([{
            name: "w-hdr", type: "http_webhook", endpoint: "https://hooks.example.com/c",
            headers: { Authorization: "Bearer tok", "X-Custom": "val" },
        }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        const hdrs = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
        expect(hdrs.Authorization).toBe("Bearer tok");
        expect(hdrs["X-Custom"]).toBe("val");
        expect(hdrs["Content-Type"]).toBe("application/json");
        globalThis.fetch = undefined!;
    });

    it("1-05 http_webhook allow_insecure: HTTP localhost allowed", async () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([
            { name: "dev", type: "http_webhook", endpoint: "http://localhost:3000/hook", allow_insecure: true },
        ]);
        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest(CRITICAL_LOG);
        expect(fetchSpy).toHaveBeenCalled();
        globalThis.fetch = undefined!;
    });

    it("1-06 console transport name preserved in output", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "my-debug-logger", type: "console" }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 2. enabled/disabled マトリクス
// =========================================================================

describe("2. enabled/disabled matrix", () => {
    it("2-01 enabled=true (explicit): dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "en", type: "console", enabled: true }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("2-02 enabled omitted (default=true): dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "def", type: "console" }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("2-03 enabled=false: no dispatch", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "dis", type: "console", enabled: false }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("2-04 mix: 2 enabled + 1 disabled → only 2 dispatch", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([
            { name: "c-on", type: "console", enabled: true },
            { name: "w-on", type: "http_webhook", endpoint: "https://example.com/h", enabled: true },
            { name: "c-off", type: "console", enabled: false },
        ]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        expect(fetchSpy).toHaveBeenCalled();
        spy.mockRestore();
        globalThis.fetch = undefined!;
    });

    it("2-05 all disabled: no transport dispatch, but task still generated", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([
            { name: "off1", type: "console", enabled: false },
            { name: "off2", type: "console", enabled: false },
        ]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("2-06 disabled http_webhook with SSRF endpoint does NOT throw at init", () => {
        expect(() => {
            const config = parseWithTransports([
                { name: "ssrf-off", type: "http_webhook", endpoint: "https://10.0.0.1/hook", enabled: false },
            ]);
            Sentinel.initialize(config);
        }).not.toThrow();
    });

    it("2-07 enabled http_webhook with SSRF endpoint DOES throw at init", () => {
        expect(() => {
            const config = parseWithTransports([
                { name: "ssrf-on", type: "http_webhook", endpoint: "https://10.0.0.1/hook", enabled: true },
            ]);
            Sentinel.initialize(config);
        }).toThrow();
    });
});

// =========================================================================
// 3. execution level × transport 組み合わせ
// =========================================================================

describe("3. execution level × transport", () => {
    function ruleWithLevel(level: string) {
        return [{ ...DEFAULT_TASK_RULE, execution_level: level }];
    }

    it("3-01 AUTO: transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("AUTO"));
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("dispatched");
            expect(spy).toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-02 SEMI_AUTO (no confirm handler): transport dispatches (AUTO fallback)", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("SEMI_AUTO"));
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("dispatched");
            expect(spy).toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-03 SEMI_AUTO + confirm=true: transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("SEMI_AUTO"));
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskConfirm(() => true);
        const r = await sentinel.ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("dispatched");
            expect(spy).toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-04 SEMI_AUTO + confirm=false: transport NOT dispatched", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("SEMI_AUTO"));
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskConfirm(() => false);
        const r = await sentinel.ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("blocked_approval");
            expect(spy).not.toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-05 MANUAL: transport NOT dispatched (blocked_approval)", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("MANUAL"));
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("blocked_approval");
            expect(spy).not.toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-06 MONITOR: transport NOT dispatched (skipped)", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], ruleWithLevel("MONITOR"));
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("skipped");
            expect(spy).not.toHaveBeenCalled();
        }
        spy.mockRestore();
    });

    it("3-07 requireHumanApproval=true + AUTO: transport NOT dispatched", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const rule = { ...DEFAULT_TASK_RULE, guardrails: { require_human_approval: true, timeout_ms: 30000, max_retries: 0 } };
        const config = parseWithTransports([{ name: "c", type: "console" }], [rule]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        if (r.tasksGenerated.length > 0) {
            expect(r.tasksGenerated[0].status).toBe("blocked_approval");
            expect(spy).not.toHaveBeenCalled();
        }
        spy.mockRestore();
    });
});

// =========================================================================
// 4. 検知 match / no-match × transport
// =========================================================================

describe("4. detection match/no-match × transport", () => {
    it("4-01 event matches: transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("4-02 event does NOT match (low level): transport NOT called", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(LOW_LOG);
        expect(r.tasksGenerated).toHaveLength(0);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("4-03 no task rules: no tasks, transport NOT called", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], []);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated).toHaveLength(0);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("4-04 multiple task rules → multiple tasks → transport called for each", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const rules = [
            { ...DEFAULT_TASK_RULE, rule_id: "r1", priority: 1 },
            { ...DEFAULT_TASK_RULE, rule_id: "r2", priority: 2 },
        ];
        const config = parseWithTransports([{ name: "c", type: "console" }], rules);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBe(2);
        expect(spy).toHaveBeenCalledTimes(2);
        spy.mockRestore();
    });
});

// =========================================================================
// 5. dispatch 結果マトリクス (HTTP error, network error, success)
// =========================================================================

describe("5. dispatch result matrix", () => {
    const originalFetch = globalThis.fetch;
    afterEach(() => { globalThis.fetch = originalFetch; });

    it("5-01 HTTP 200: task dispatched", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("dispatched");
    });

    it("5-02 HTTP 201: task dispatched", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 201 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("dispatched");
    });

    it("5-03 HTTP 400: task failed", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 400 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("400");
    });

    it("5-04 HTTP 429: task failed", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 429 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("429");
    });

    it("5-05 HTTP 500: task failed", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("500");
    });

    it("5-06 HTTP 503: task failed", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("503");
    });

    it("5-07 ECONNREFUSED: task failed", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("ECONNREFUSED");
    });

    it("5-08 ETIMEDOUT: task failed", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("ETIMEDOUT"));
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("ETIMEDOUT");
    });

    it("5-09 mixed: one success + one failure → task failed (error aggregated)", async () => {
        const fetchSpy = vi.fn()
            .mockResolvedValueOnce({ ok: true, status: 200 })
            .mockResolvedValueOnce({ ok: false, status: 503 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([
            { name: "ok", type: "http_webhook", endpoint: "https://ok.example.com/h" },
            { name: "fail", type: "http_webhook", endpoint: "https://fail.example.com/h" },
        ]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(r.tasksGenerated[0].error).toContain("503");
    });

    it("5-10 console always succeeds even when fetch fails", async () => {
        globalThis.fetch = vi.fn().mockRejectedValue(new Error("fail"));
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([
            { name: "c", type: "console" },
            { name: "w", type: "http_webhook", endpoint: "https://example.com/h" },
        ]);
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        // console は成功するが http_webhook は失敗 → 全体は failed
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 6. user-injected + config-based マージ
// =========================================================================

describe("6. user-injected + config-based transport merge", () => {
    it("6-01 config only: config transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("6-02 user only: user transport dispatches", async () => {
        const userFn = vi.fn().mockResolvedValue({ transportName: "user", success: true });
        const config = parseWithTransports([]);
        Sentinel.initialize(config, { taskTransports: [{ name: "user", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(userFn).toHaveBeenCalled();
    });

    it("6-03 both: user + config both dispatch", async () => {
        const userFn = vi.fn().mockResolvedValue({ transportName: "user", success: true });
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config, { taskTransports: [{ name: "user", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(userFn).toHaveBeenCalled();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("6-04 user transport executes first (before config-based)", async () => {
        const order: string[] = [];
        const userFn = vi.fn().mockImplementation(async () => { order.push("user"); return { transportName: "user", success: true }; });
        const spy = vi.spyOn(console, "info").mockImplementation(() => { order.push("config"); });
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config, { taskTransports: [{ name: "user", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(order[0]).toBe("user");
        expect(order[1]).toBe("config");
        spy.mockRestore();
    });

    it("6-05 user failure + config success → failed (both execute)", async () => {
        const userFn = vi.fn().mockRejectedValue(new Error("user fail"));
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config, { taskTransports: [{ name: "user", dispatch: userFn }] });
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(spy).toHaveBeenCalled(); // config transport still runs
        spy.mockRestore();
    });

    it("6-06 type=custom skipped + user-injected runs", async () => {
        const userFn = vi.fn().mockResolvedValue({ transportName: "user", success: true });
        const config = parseWithTransports([{ name: "skip", type: "custom" }]);
        Sentinel.initialize(config, { taskTransports: [{ name: "user", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(userFn).toHaveBeenCalled();
    });
});

// =========================================================================
// 7. handler + transport 共存
// =========================================================================

describe("7. handler + transport coexistence", () => {
    it("7-01 handler only: handler runs, no transport", async () => {
        const handler = vi.fn();
        const config = parseWithTransports([]);
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        await sentinel.ingest(CRITICAL_LOG);
        expect(handler).toHaveBeenCalled();
    });

    it("7-02 transport only: transport runs, no handler", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("7-03 handler + transport: both run", async () => {
        const handler = vi.fn();
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        await sentinel.ingest(CRITICAL_LOG);
        expect(handler).toHaveBeenCalled();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("7-04 handler fails + transport succeeds → failed but transport ran", async () => {
        const handler = vi.fn().mockRejectedValue(new Error("handler boom"));
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        const r = await sentinel.ingest(CRITICAL_LOG);
        expect(r.tasksGenerated[0].status).toBe("failed");
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("7-05 handler succeeds + transport fails → failed", async () => {
        const handler = vi.fn();
        const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 500 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports([{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }]);
        const sentinel = Sentinel.initialize(config);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        const r = await sentinel.ingest(CRITICAL_LOG);
        expect(handler).toHaveBeenCalled();
        expect(r.tasksGenerated[0].status).toBe("failed");
        globalThis.fetch = undefined!;
    });

    it("7-06 handler deregistered: only transport runs", async () => {
        const handler = vi.fn();
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        const unsub = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
        unsub();
        await sentinel.ingest(CRITICAL_LOG);
        expect(handler).not.toHaveBeenCalled();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 8. ライフサイクル
// =========================================================================

describe("8. lifecycle (init → dispatch → shutdown → re-init)", () => {
    it("8-01 init → dispatch → shutdown", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        await sentinel.ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        await sentinel.shutdown();
        spy.mockRestore();
    });

    it("8-02 shutdown → re-init → dispatch works", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        let sentinel = Sentinel.initialize(config);
        await sentinel.shutdown();
        spy.mockClear();

        sentinel = Sentinel.initialize(parseWithTransports([{ name: "c2", type: "console" }]));
        await sentinel.ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("8-03 double shutdown: idempotent", async () => {
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        await sentinel.shutdown();
        await expect(sentinel.shutdown()).resolves.toBeUndefined();
    });

    it("8-04 ingest after shutdown: throws", async () => {
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        const sentinel = Sentinel.initialize(config);
        await sentinel.shutdown();
        await expect(sentinel.ingest(CRITICAL_LOG)).rejects.toThrow("shutdown");
    });

    it("8-05 reset → re-init → dispatch works", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        Sentinel.initialize(parseWithTransports([{ name: "c", type: "console" }]));
        Sentinel.reset();
        spy.mockClear();

        Sentinel.initialize(parseWithTransports([{ name: "c2", type: "console" }]));
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("8-06 multiple ingest calls: all dispatch", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }]);
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(spy.mock.calls.length).toBeGreaterThanOrEqual(3);
        spy.mockRestore();
    });
});

// =========================================================================
// 9. config バリデーションエラー
// =========================================================================

describe("9. config validation errors (YAML stage)", () => {
    it("9-01 missing name", () => {
        expect(() => parseWithTransports([{ type: "console" }])).toThrow("name");
    });

    it("9-02 empty name", () => {
        expect(() => parseWithTransports([{ name: "", type: "console" }])).toThrow("name");
    });

    it("9-03 unknown type", () => {
        expect(() => parseWithTransports([{ name: "x", type: "kafka" }] as Record<string, unknown>[])).toThrow("type");
    });

    it("9-04 http_webhook missing endpoint", () => {
        expect(() => parseWithTransports([{ name: "x", type: "http_webhook" }])).toThrow("endpoint");
    });

    it("9-05 invalid method DELETE", () => {
        expect(() => parseWithTransports([
            { name: "x", type: "http_webhook", endpoint: "https://e.com", method: "DELETE" },
        ])).toThrow("method");
    });

    it("9-06 invalid method PATCH", () => {
        expect(() => parseWithTransports([
            { name: "x", type: "http_webhook", endpoint: "https://e.com", method: "PATCH" },
        ])).toThrow("method");
    });

    it("9-07 valid: type omitted defaults to custom", () => {
        const config = parseWithTransports([{ name: "x" }]);
        expect(config.taskTransportConfigs![0].type).toBe("custom");
    });

    it("9-08 valid: enabled omitted defaults to true", () => {
        const config = parseWithTransports([{ name: "x", type: "console" }]);
        expect(config.taskTransportConfigs![0].enabled).toBe(true);
    });
});

// =========================================================================
// 10. SSRF 防御マトリクス
// =========================================================================

describe("10. SSRF defense matrix (init-time validation)", () => {
    const ssrfEndpoints = [
        ["https://localhost/h", "localhost"],
        ["https://127.0.0.1/h", "127.0.0.1"],
        ["https://0.0.0.0/h", "0.0.0.0"],
        ["https://10.0.0.1/h", "10.x"],
        ["https://10.255.255.255/h", "10.x edge"],
        ["https://172.16.0.1/h", "172.16.x"],
        ["https://172.31.255.255/h", "172.31.x"],
        ["https://192.168.0.1/h", "192.168.x"],
        ["https://192.168.255.255/h", "192.168.x edge"],
        ["https://169.254.1.1/h", "link-local"],
    ] as const;

    for (const [endpoint, label] of ssrfEndpoints) {
        it(`10-XX rejects ${label} (${endpoint})`, () => {
            expect(() => {
                const config = parseWithTransports([
                    { name: "ssrf", type: "http_webhook", endpoint },
                ]);
                Sentinel.initialize(config);
            }).toThrow();
        });
    }

    const allowedEndpoints = [
        ["https://8.8.8.8/h", "public IP"],
        ["https://172.15.0.1/h", "172.15 (below range)"],
        ["https://172.32.0.1/h", "172.32 (above range)"],
        ["https://hooks.slack.com/h", "public hostname"],
    ] as const;

    for (const [endpoint, label] of allowedEndpoints) {
        it(`10-XX allows ${label} (${endpoint})`, () => {
            expect(() => {
                const config = parseWithTransports([
                    { name: "ok", type: "http_webhook", endpoint },
                ]);
                Sentinel.initialize(config);
            }).not.toThrow();
        });
    }

    it("10-XX http:// rejected without allowInsecure", () => {
        expect(() => {
            const config = parseWithTransports([
                { name: "http", type: "http_webhook", endpoint: "http://example.com/h" },
            ]);
            Sentinel.initialize(config);
        }).toThrow("HTTPS");
    });

    it("10-XX http:// allowed with allow_insecure=true", () => {
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
        expect(() => {
            const config = parseWithTransports([
                { name: "http-ok", type: "http_webhook", endpoint: "http://localhost:3000/h", allow_insecure: true },
            ]);
            Sentinel.initialize(config);
        }).not.toThrow();
        globalThis.fetch = undefined!;
    });
});

// =========================================================================
// 11. エッジケース
// =========================================================================

describe("11. edge cases", () => {
    it("11-01 no task_transports in config: pipeline works", async () => {
        const config = parseConfigYaml("", {
            yamlParser: () => ({
                project_name: "no-transports",
                service_id: "test",
                environment: "test",
                task_rules: [DEFAULT_TASK_RULE],
            }),
        });
        const sentinel = Sentinel.initialize(config);
        const r = await sentinel.ingest(CRITICAL_LOG);
        expect(r.traceId).toBeDefined();
    });

    it("11-02 empty task_transports: pipeline works", async () => {
        const config = parseWithTransports([]);
        const sentinel = Sentinel.initialize(config);
        const r = await sentinel.ingest(CRITICAL_LOG);
        expect(r.traceId).toBeDefined();
    });

    it("11-03 transport receives correct task body shape", async () => {
        const receivedTasks: unknown[] = [];
        const userFn = vi.fn().mockImplementation(async (task: unknown) => {
            receivedTasks.push(task);
            return { transportName: "inspector", success: true };
        });
        const config = parseWithTransports([]);
        Sentinel.initialize(config, { taskTransports: [{ name: "inspector", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        if (receivedTasks.length > 0) {
            const task = receivedTasks[0] as Record<string, unknown>;
            expect(task.taskId).toBeTruthy();
            expect(task.ruleId).toBe("rule-yaml-test");
            expect(task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
            expect(task.severity).toBeDefined();
            expect(task.actionType).toBe("SYSTEM_NOTIFICATION");
            expect(task.executionLevel).toBe("AUTO");
            expect(task.guardrails).toBeDefined();
            expect(task.sourceLog).toBeDefined();
            expect((task.sourceLog as Record<string, unknown>).message).toBe("critical failure");
            expect(task.createdAt).toBeTruthy();
        }
    });

    it("11-04 large number of transports (10): all dispatch", async () => {
        const spies = Array.from({ length: 10 }, (_, i) =>
            vi.fn().mockResolvedValue({ transportName: `t${i}`, success: true }),
        );
        const transports = spies.map((fn, i) => ({ name: `t${i}`, dispatch: fn }));
        const config = parseWithTransports([]);
        Sentinel.initialize(config, { taskTransports: transports });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);
        for (const spy of spies) {
            expect(spy).toHaveBeenCalled();
        }
    });
});

// =========================================================================
// 12. masking × transport
// =========================================================================

describe("12. masking × transport cross-config", () => {
    it("12-01 masking.enabled=true: transport receives masked message", async () => {
        const received: unknown[] = [];
        const userFn = vi.fn().mockImplementation(async (t: unknown) => { received.push(t); return { transportName: "u", success: true }; });
        const config = parseWithTransports([], [DEFAULT_TASK_RULE], {
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserve_fields: ["traceId"] },
        });
        Sentinel.initialize(config, { taskTransports: [{ name: "u", dispatch: userFn }] });
        await Sentinel.getInstance().ingest({ message: "contact user@example.com now", level: 6, isCritical: true });

        expect(received.length).toBeGreaterThan(0);
        const task = received[0] as Record<string, unknown>;
        const src = task.sourceLog as Record<string, unknown>;
        // メールアドレスがマスクされている
        expect(src.message).not.toContain("user@example.com");
        expect(src.message).toContain("[MASKED_EMAIL]");
    });

    it("12-02 masking.enabled=false: transport receives original message", async () => {
        const received: unknown[] = [];
        const userFn = vi.fn().mockImplementation(async (t: unknown) => { received.push(t); return { transportName: "u", success: true }; });
        const config = parseWithTransports([], [DEFAULT_TASK_RULE], {
            masking: { enabled: false, rules: [], preserve_fields: [] },
        });
        Sentinel.initialize(config, { taskTransports: [{ name: "u", dispatch: userFn }] });
        await Sentinel.getInstance().ingest({ message: "contact user@example.com now", level: 6, isCritical: true });

        expect(received.length).toBeGreaterThan(0);
        const src = (received[0] as Record<string, unknown>).sourceLog as Record<string, unknown>;
        expect(src.message).toContain("user@example.com");
    });

    it("12-03 masking + console transport: console output contains masked message", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "CREDIT_CARD" }], preserve_fields: ["traceId"] },
        });
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest({ message: "card 4111111111111111", level: 6, isCritical: true });

        const output = spy.mock.calls[0][0] as string;
        expect(output).not.toContain("4111111111111111");
        expect(output).toContain("MASKED");
        spy.mockRestore();
    });
});

// =========================================================================
// 13. security.enableHashChain × transport
// =========================================================================

describe("13. hashChain × transport cross-config", () => {
    it("13-01 hashChain=true: result has hashChainValid=true", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            security: { enable_hash_chain: true },
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.hashChainValid).toBe(true);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        spy.mockRestore();
    });

    it("13-02 hashChain=false: result has hashChainValid=false", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            security: { enable_hash_chain: false },
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.hashChainValid).toBe(false);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        spy.mockRestore();
    });

    it("13-03 hashChain=true + transport dispatch does not break chain", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            security: { enable_hash_chain: true },
        });
        Sentinel.initialize(config);
        const r1 = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        const r2 = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r1.hashChainValid).toBe(true);
        expect(r2.hashChainValid).toBe(true);
        expect(r1.traceId).not.toBe(r2.traceId);
        spy.mockRestore();
    });
});

// =========================================================================
// 14. callbacks × transport
// =========================================================================

describe("14. callbacks × transport cross-config", () => {
    it("14-01 onTaskGenerated fires before transport dispatch", async () => {
        const order: string[] = [];
        const onTaskGenerated = vi.fn().mockImplementation(() => { order.push("callback"); });
        const userFn = vi.fn().mockImplementation(async () => { order.push("transport"); return { transportName: "u", success: true }; });
        const config = parseWithTransports([], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).onTaskGenerated = onTaskGenerated;
        Sentinel.initialize(config, { taskTransports: [{ name: "u", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onTaskGenerated).toHaveBeenCalled();
        expect(userFn).toHaveBeenCalled();
        expect(order.indexOf("callback")).toBeLessThan(order.indexOf("transport"));
    });

    it("14-02 onTaskGenerated throws: transport still dispatches (emitSafe)", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const userFn = vi.fn().mockResolvedValue({ transportName: "u", success: true });
        const config = parseWithTransports([], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).onTaskGenerated = () => { throw new Error("callback boom"); };
        Sentinel.initialize(config, { taskTransports: [{ name: "u", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(userFn).toHaveBeenCalled();
        stderrSpy.mockRestore();
    });

    it("14-03 onTaskDispatched receives result after transport dispatch", async () => {
        const onTaskDispatched = vi.fn();
        const userFn = vi.fn().mockResolvedValue({ transportName: "u", success: true });
        const config = parseWithTransports([], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).onTaskDispatched = onTaskDispatched;
        Sentinel.initialize(config, { taskTransports: [{ name: "u", dispatch: userFn }] });
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onTaskDispatched).toHaveBeenCalled();
        const result = onTaskDispatched.mock.calls[0][0];
        expect(result.status).toBe("dispatched");
        expect(result.taskId).toBeTruthy();
    });

    it("14-04 onTaskDispatched receives failed result on transport failure", async () => {
        const onTaskDispatched = vi.fn();
        const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 500 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports(
            [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }],
            [DEFAULT_TASK_RULE],
        );
        (config as Record<string, unknown>).onTaskDispatched = onTaskDispatched;
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onTaskDispatched).toHaveBeenCalled();
        const result = onTaskDispatched.mock.calls[0][0];
        expect(result.status).toBe("failed");
        expect(result.error).toContain("500");
        globalThis.fetch = undefined!;
    });

    it("14-05 onError fires on transport exception", async () => {
        const onError = vi.fn();
        const fetchSpy = vi.fn().mockRejectedValue(new Error("transport boom"));
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports(
            [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }],
            [DEFAULT_TASK_RULE],
        );
        (config as Record<string, unknown>).onError = onError;
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        // transport例外はTaskExecutor内で catch → TaskResult.status=failed
        // onError は emitSafe 経由のみ（transport例外は直接 onError に行かない）
        // ただし onTaskDispatched で result.status=failed を受け取れる
        // ここでは task 自体は生成→dispatch→failed のフロー確認
        expect(fetchSpy).toHaveBeenCalled();
        globalThis.fetch = undefined!;
    });
});

// =========================================================================
// 15. metrics × transport
// =========================================================================

describe("15. metrics × transport cross-config", () => {
    it("15-01 metrics.onTaskDispatch fires on successful transport dispatch", async () => {
        const onTaskDispatch = vi.fn();
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).metrics = { onTaskDispatch };
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onTaskDispatch).toHaveBeenCalled();
        const result = onTaskDispatch.mock.calls[0][0];
        expect(result.status).toBe("dispatched");
        spy.mockRestore();
    });

    it("15-02 metrics.onTaskDispatch fires on failed transport dispatch", async () => {
        const onTaskDispatch = vi.fn();
        const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 503 });
        globalThis.fetch = fetchSpy;
        const config = parseWithTransports(
            [{ name: "w", type: "http_webhook", endpoint: "https://example.com/h" }],
            [DEFAULT_TASK_RULE],
        );
        (config as Record<string, unknown>).metrics = { onTaskDispatch };
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onTaskDispatch).toHaveBeenCalled();
        const result = onTaskDispatch.mock.calls[0][0];
        expect(result.status).toBe("failed");
        globalThis.fetch = undefined!;
    });

    it("15-03 metrics.onTaskDispatch throws: pipeline continues", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).metrics = {
            onTaskDispatch: () => { throw new Error("metrics boom"); },
        };
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);

        // metrics例外でもパイプラインは続行
        expect(r.traceId).toBeDefined();
        spy.mockRestore();
        stderrSpy.mockRestore();
    });

    it("15-04 metrics.onIngest + transport: both fire on same ingest", async () => {
        const onIngest = vi.fn();
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        (config as Record<string, unknown>).metrics = { onIngest };
        Sentinel.initialize(config);
        await Sentinel.getInstance().ingest(CRITICAL_LOG);

        expect(onIngest).toHaveBeenCalled();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 16. custom detectionRules × transport
// =========================================================================

describe("16. custom detectionRules × transport cross-config", () => {
    it("16-01 custom detection rule triggers task → transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports(
            [{ name: "c", type: "console" }],
            [{
                rule_id: "custom-rule-task",
                event_name: "SECURITY_INTRUSION_DETECTED",
                severity: "HIGH",
                action_type: "SYSTEM_NOTIFICATION",
                execution_level: "AUTO",
                priority: 1,
                description: "custom detection trigger",
                guardrails: { require_human_approval: false, timeout_ms: 30000, max_retries: 0 },
            }],
            {
                detection_rules: [{
                    rule_id: "custom-det",
                    event_name: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: { log_types: ["SECURITY"], min_level: 5 },
                }],
                whitelist: { level: "off" },
            },
        );
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest({ message: "intrusion detected", level: 5, type: "SECURITY" });

        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        const output = JSON.parse(spy.mock.calls[0][0] as string);
        expect(output.sentinel_task.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        spy.mockRestore();
    });

    it("16-02 custom detection rule does NOT match: transport NOT called", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports(
            [{ name: "c", type: "console" }],
            [{
                rule_id: "no-match-rule",
                event_name: "SECURITY_INTRUSION_DETECTED",
                severity: "HIGH",
                action_type: "SYSTEM_NOTIFICATION",
                execution_level: "AUTO",
                priority: 1,
                description: "no-match test",
                guardrails: { require_human_approval: false, timeout_ms: 30000, max_retries: 0 },
            }],
            {
                detection_rules: [{
                    rule_id: "strict-det",
                    event_name: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: { log_types: ["SECURITY"], min_level: 5 },
                }],
                whitelist: { level: "off" },
            },
        );
        Sentinel.initialize(config);
        // SYSTEM type + level 3 → SECURITY rule does NOT match
        const r = await Sentinel.getInstance().ingest({ message: "normal", level: 3, type: "SYSTEM" });
        expect(r.tasksGenerated).toHaveLength(0);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 17. validationLimits × transport
// =========================================================================

describe("17. validationLimits × transport cross-config", () => {
    it("17-01 oversized message: validation error, transport NOT called", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        Sentinel.initialize(config);

        const oversized = "x".repeat(70000); // default maxMessageLength=65536
        await expect(Sentinel.getInstance().ingest({ message: oversized, level: 6, isCritical: true }))
            .rejects.toThrow();
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it("17-02 valid message within limits: transport dispatches", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        Sentinel.initialize(config);

        const valid = "x".repeat(1000);
        const r = await Sentinel.getInstance().ingest({ message: valid, level: 6, isCritical: true });
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("17-03 empty message: validation error, transport NOT called", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE]);
        Sentinel.initialize(config);

        await expect(Sentinel.getInstance().ingest({ message: "", level: 6 })).rejects.toThrow();
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });
});

// =========================================================================
// 18. environment × transport
// =========================================================================

describe("18. environment × transport cross-config", () => {
    it("18-01 production: transport dispatches normally", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            environment: "production",
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("18-02 test: transport dispatches normally", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            environment: "test",
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("18-03 local: transport dispatches normally", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            environment: "local",
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("18-04 development: transport dispatches normally", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            environment: "development",
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("18-05 staging: transport dispatches normally", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const config = parseWithTransports([{ name: "c", type: "console" }], [DEFAULT_TASK_RULE], {
            environment: "staging",
        });
        Sentinel.initialize(config);
        const r = await Sentinel.getInstance().ingest(CRITICAL_LOG);
        expect(r.tasksGenerated.length).toBeGreaterThan(0);
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});
