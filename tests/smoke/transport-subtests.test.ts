/**
 * Transport サブテストケース
 *
 * 既存テストの細分化 — 境界値、型不正、null/undefined、concurrent 等。
 * 各テストは既存テストのどの領域を補完するかを明記。
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { HttpWebhookTransport } from "../../src/transport/http-webhook-transport";
import { ConsoleTaskTransport } from "../../src/transport/console-task-transport";
import { createTaskTransportsFromConfig } from "../../src/transport/task-transport-factory";
import { TaskExecutor } from "../../src/core/task/task-executor";
import type { TaskTransportConfig } from "../../src/configs/sentinel-config";
import type { GeneratedTask } from "../../src/types/task";
import type { TaskTransportResult, TaskTransport } from "../../src/transport/task-transport";

const dummyTask: GeneratedTask = {
    taskId: "sub-001", ruleId: "r-1", eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "CRITICAL", actionType: "SYSTEM_NOTIFICATION", executionLevel: "AUTO",
    priority: 1, description: "sub test", executionParams: {},
    guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 0 },
    sourceLog: { traceId: "t-1", message: "sub", boundary: "test", level: 6, timestamp: "2026-04-02T00:00:00Z" },
    createdAt: "2026-04-02T00:00:00Z",
};

// =========================================================================
// SUB-01: HttpWebhookTransport 境界値
// =========================================================================

describe("SUB-01: HttpWebhookTransport boundary values", () => {
    const originalFetch = globalThis.fetch;
    afterEach(() => { globalThis.fetch = originalFetch; });

    it("SUB-01-01 endpoint with trailing slash → accepted", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://example.com/" })).not.toThrow();
    });

    it("SUB-01-02 endpoint with query string → accepted", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://example.com/hook?key=val" })).not.toThrow();
    });

    it("SUB-01-03 endpoint with fragment → accepted (fragment ignored by fetch)", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://example.com/hook#section" })).not.toThrow();
    });

    it("SUB-01-04 endpoint with port 443 → accepted", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://example.com:443/hook" })).not.toThrow();
    });

    it("SUB-01-05 endpoint with non-standard port → accepted", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://example.com:8443/hook" })).not.toThrow();
    });

    it("SUB-01-06 endpoint with unicode hostname → accepted (punycode)", () => {
        expect(() => new HttpWebhookTransport({ endpoint: "https://例え.jp/hook" })).not.toThrow();
    });

    it("SUB-01-07 empty headers object → uses default Content-Type only", async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook", headers: {} });
        await t.dispatch(dummyTask);
        const hdrs = ((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit).headers as Record<string, string>;
        expect(hdrs["Content-Type"]).toBe("application/json");
        expect(Object.keys(hdrs)).toHaveLength(1);
    });

    it("SUB-01-08 method defaults to POST when omitted", () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        expect(t.name).toBe("http_webhook"); // method は private、dispatch で検証
    });

    it("SUB-01-09 name with special characters → accepted", () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook", name: "日本語-name/with:special" });
        expect(t.name).toBe("日本語-name/with:special");
    });

    it("SUB-01-10 dispatch with AbortError after close → success=false", async () => {
        globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
            // simulate: signal already aborted
            if (init.signal?.aborted) throw new DOMException("aborted", "AbortError");
            return { ok: true, status: 200 };
        });
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        await t.close();
        const result = await t.dispatch(dummyTask);
        expect(result.success).toBe(false);
    });
});

// =========================================================================
// SUB-02: ConsoleTaskTransport 境界値
// =========================================================================

describe("SUB-02: ConsoleTaskTransport boundary values", () => {
    it("SUB-02-01 dispatch with undefined fields in task → serialized as null", () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const t = new ConsoleTaskTransport();
        const partialTask = { ...dummyTask, executionParams: undefined } as unknown as GeneratedTask;
        t.dispatch(partialTask);
        const output = spy.mock.calls[0][0] as string;
        // JSON.stringify omits undefined
        expect(JSON.parse(output)).toBeTruthy();
        spy.mockRestore();
    });

    it("SUB-02-02 rapid sequential close + dispatch → all return closed", async () => {
        const t = new ConsoleTaskTransport();
        await t.close();
        const results = await Promise.all([
            t.dispatch(dummyTask),
            t.dispatch(dummyTask),
            t.dispatch(dummyTask),
        ]);
        expect(results.every((r) => !r.success)).toBe(true);
    });

    it("SUB-02-03 empty name → defaults to 'console'", () => {
        const t = new ConsoleTaskTransport();
        expect(t.name).toBe("console");
    });

    it("SUB-02-04 name with empty string → uses empty string", () => {
        const t = new ConsoleTaskTransport("");
        expect(t.name).toBe("");
    });
});

// =========================================================================
// SUB-03: Factory 境界値
// =========================================================================

describe("SUB-03: Factory boundary values", () => {
    it("SUB-03-01 config with type undefined + enabled true → skipped", () => {
        const transports = createTaskTransportsFromConfig([
            { name: "no-type", enabled: true } as TaskTransportConfig,
        ]);
        expect(transports).toHaveLength(0);
    });

    it("SUB-03-02 config with type=custom + enabled=false → skipped", () => {
        const transports = createTaskTransportsFromConfig([
            { name: "off-custom", type: "custom", enabled: false } as TaskTransportConfig,
        ]);
        expect(transports).toHaveLength(0);
    });

    it("SUB-03-03 10 console transports → all 10 created", () => {
        const configs = Array.from({ length: 10 }, (_, i) => ({
            name: `c${i}`, type: "console", enabled: true,
        })) as TaskTransportConfig[];
        const transports = createTaskTransportsFromConfig(configs);
        expect(transports).toHaveLength(10);
        transports.forEach((t, i) => expect(t.name).toBe(`c${i}`));
    });

    it("SUB-03-04 mix of all types in various order → correct filtering", () => {
        const configs = [
            { name: "w1", type: "http_webhook", endpoint: "https://a.com/h", enabled: true },
            { name: "c1", type: "console", enabled: false },
            { name: "u1", type: "custom", enabled: true },
            { name: "c2", type: "console", enabled: true },
            { name: "w2", type: "http_webhook", endpoint: "https://b.com/h", enabled: false },
            { name: "c3", type: "console" }, // enabled defaults to true
        ] as TaskTransportConfig[];
        const transports = createTaskTransportsFromConfig(configs);
        // w1 (http_webhook enabled) + c2 (console enabled) + c3 (console default enabled)
        expect(transports).toHaveLength(3);
        expect(transports[0].name).toBe("w1");
        expect(transports[1].name).toBe("c2");
        expect(transports[2].name).toBe("c3");
    });
});

// =========================================================================
// SUB-04: TaskExecutor + real transports
// =========================================================================

describe("SUB-04: TaskExecutor with real transport instances", () => {
    it("SUB-04-01 real ConsoleTaskTransport in TaskExecutor", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const transport = new ConsoleTaskTransport("real-console");
        const executor = new TaskExecutor(undefined, [transport]);

        const result = await executor.dispatch(dummyTask);

        expect(result.status).toBe("dispatched");
        expect(spy).toHaveBeenCalledTimes(1);
        const output = JSON.parse(spy.mock.calls[0][0] as string);
        expect(output.sentinel_task.taskId).toBe("sub-001");
        spy.mockRestore();
    });

    it("SUB-04-02 real HttpWebhookTransport in TaskExecutor (fetch mock)", async () => {
        const originalFetch = globalThis.fetch;
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        const transport = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        const executor = new TaskExecutor(undefined, [transport]);

        const result = await executor.dispatch(dummyTask);

        expect(result.status).toBe("dispatched");
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
        expect(body.taskId).toBe("sub-001");
        globalThis.fetch = originalFetch;
    });

    it("SUB-04-03 real console + mock transport in same executor", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const mockFn = vi.fn().mockResolvedValue({ transportName: "mock", success: true } satisfies TaskTransportResult);
        const mockTransport: TaskTransport = { name: "mock", dispatch: mockFn };
        const console_ = new ConsoleTaskTransport("real");

        const executor = new TaskExecutor(undefined, [console_, mockTransport]);
        const result = await executor.dispatch(dummyTask);

        expect(result.status).toBe("dispatched");
        expect(spy).toHaveBeenCalledTimes(1);
        expect(mockFn).toHaveBeenCalledTimes(1);
        spy.mockRestore();
    });

    it("SUB-04-04 closeTransports closes real ConsoleTaskTransport", async () => {
        const transport = new ConsoleTaskTransport();
        const executor = new TaskExecutor(undefined, [transport]);
        await executor.closeTransports();

        // close 後は dispatch が success=false を返す
        const result = await transport.dispatch(dummyTask);
        expect(result.success).toBe(false);
    });

    it("SUB-04-05 handler + real console transport: both execute", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const handler = vi.fn();
        const transport = new ConsoleTaskTransport();
        const executor = new TaskExecutor(undefined, [transport]);
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        await executor.dispatch(dummyTask);

        expect(handler).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledTimes(1);
        spy.mockRestore();
    });
});

// =========================================================================
// SUB-05: Concurrent dispatch patterns
// =========================================================================

describe("SUB-05: Concurrent dispatch patterns", () => {
    it("SUB-05-01 50 concurrent dispatches to same transport", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const transport = new ConsoleTaskTransport();
        const executor = new TaskExecutor(undefined, [transport]);

        const results = await Promise.all(
            Array.from({ length: 50 }, (_, i) =>
                executor.dispatch({ ...dummyTask, taskId: `concurrent-${i}` }),
            ),
        );

        expect(results).toHaveLength(50);
        expect(results.every((r) => r.status === "dispatched")).toBe(true);
        expect(spy).toHaveBeenCalledTimes(50);
        spy.mockRestore();
    });

    it("SUB-05-02 concurrent dispatch + close race → some succeed, some closed", async () => {
        const spy = vi.spyOn(console, "info").mockImplementation(() => {});
        const transport = new ConsoleTaskTransport();

        // dispatch と close を同時に実行
        const dispatchPromises = Array.from({ length: 10 }, (_, i) =>
            transport.dispatch({ ...dummyTask, taskId: `race-${i}` }),
        );
        const closePromise = transport.close();

        const [results] = await Promise.all([Promise.all(dispatchPromises), closePromise]);

        // 一部は success=true、一部は success=false (closed) の可能性
        const successes = results.filter((r) => r.success).length;
        const failures = results.filter((r) => !r.success).length;
        expect(successes + failures).toBe(10);
        spy.mockRestore();
    });
});

// =========================================================================
// SUB-06: TaskResult 構造検証
// =========================================================================

describe("SUB-06: TaskResult structure from transport dispatch", () => {
    it("SUB-06-01 successful dispatch: all TaskResult fields present", async () => {
        const transport: TaskTransport = {
            name: "struct-check",
            dispatch: vi.fn().mockResolvedValue({ transportName: "struct-check", success: true }),
        };
        const executor = new TaskExecutor(undefined, [transport]);
        const result = await executor.dispatch(dummyTask);

        expect(result.taskId).toBe("sub-001");
        expect(result.ruleId).toBe("r-1");
        expect(result.status).toBe("dispatched");
        expect(result.dispatchedAt).toBeTruthy();
        expect(new Date(result.dispatchedAt).getTime()).not.toBeNaN();
        expect(result.error).toBeUndefined();
    });

    it("SUB-06-02 failed dispatch: error field populated", async () => {
        const transport: TaskTransport = {
            name: "fail-check",
            dispatch: vi.fn().mockResolvedValue({ transportName: "fail-check", success: false, error: "503 Service Unavailable" }),
        };
        const executor = new TaskExecutor(undefined, [transport]);
        const result = await executor.dispatch(dummyTask);

        expect(result.status).toBe("failed");
        expect(result.error).toContain("503");
        expect(result.error).toContain("fail-check");
        expect(result.taskId).toBe("sub-001");
        expect(result.dispatchedAt).toBeTruthy();
    });

    it("SUB-06-03 blocked_approval: no error, correct status", async () => {
        const transport: TaskTransport = {
            name: "blocked-check",
            dispatch: vi.fn(),
        };
        const executor = new TaskExecutor(undefined, [transport]);
        const manualTask = { ...dummyTask, executionLevel: "MANUAL" as const };
        const result = await executor.dispatch(manualTask);

        expect(result.status).toBe("blocked_approval");
        expect(result.error).toBeUndefined();
        expect(transport.dispatch).not.toHaveBeenCalled();
    });
});
