import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HttpWebhookTransport } from "../../../src/transport/http-webhook-transport";
import type { GeneratedTask } from "../../../src/types/task";

function createTask(overrides: Partial<GeneratedTask> = {}): GeneratedTask {
    return {
        taskId: "task-001", ruleId: "rule-001",
        eventName: "SYSTEM_CRITICAL_FAILURE", severity: "CRITICAL",
        actionType: "SYSTEM_NOTIFICATION", executionLevel: "AUTO",
        priority: 1, description: "Test task", executionParams: {},
        guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 0 },
        sourceLog: { traceId: "t-1", message: "test", boundary: "db", level: 6, timestamp: "2026-04-02T00:00:00Z" },
        createdAt: "2026-04-02T00:00:00Z",
        ...overrides,
    };
}

// =========================================================================
// コンストラクタ: URL バリデーション
// =========================================================================

describe("HttpWebhookTransport: constructor URL validation", () => {
    it("accepts valid HTTPS URL", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://hooks.slack.com/services/xxx",
        })).not.toThrow();
    });

    it("rejects HTTP URL by default", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "http://example.com/hook",
        })).toThrow("HTTPS");
    });

    it("allows HTTP with allowInsecure: true", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "http://example.com/hook",
            allowInsecure: true,
        })).not.toThrow();
    });

    it("rejects localhost", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://localhost/hook",
        })).toThrow();
    });

    it("rejects 127.0.0.1", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://127.0.0.1/hook",
        })).toThrow();
    });

    it("rejects private IP 10.x.x.x", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://10.0.0.1/hook",
        })).toThrow();
    });

    it("rejects private IP 192.168.x.x", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://192.168.1.1/hook",
        })).toThrow();
    });

    it("rejects private IP 172.16-31.x.x", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://172.16.0.1/hook",
        })).toThrow();
        expect(() => new HttpWebhookTransport({
            endpoint: "https://172.31.255.255/hook",
        })).toThrow();
    });

    it("allows private IPs with allowInsecure: true", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "http://localhost:3000/hook",
            allowInsecure: true,
        })).not.toThrow();
    });

    it("allows 172.15.x.x (just outside private range)", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://172.15.0.1/hook",
        })).not.toThrow();
    });

    it("allows 172.32.x.x (above private range)", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://172.32.0.1/hook",
        })).not.toThrow();
    });

    it("rejects 169.254.x.x (link-local)", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://169.254.1.1/hook",
        })).toThrow();
    });

    it("rejects 0.0.0.0", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "https://0.0.0.0/hook",
        })).toThrow();
    });

    it("rejects empty string endpoint", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "",
        })).toThrow();
    });

    it("rejects invalid URL", () => {
        expect(() => new HttpWebhookTransport({
            endpoint: "not-a-url",
        })).toThrow();
    });

    it("defaults name to http_webhook", () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        expect(t.name).toBe("http_webhook");
    });

    it("accepts custom name", () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook", name: "slack" });
        expect(t.name).toBe("slack");
    });
});

// =========================================================================
// dispatch: fetch 呼び出し
// =========================================================================

describe("HttpWebhookTransport: dispatch", () => {
    let fetchSpy: ReturnType<typeof vi.fn>;
    const originalFetch = globalThis.fetch;

    beforeEach(() => {
        fetchSpy = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
        });
        globalThis.fetch = fetchSpy;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it("calls fetch with correct URL, method, headers, body", async () => {
        const t = new HttpWebhookTransport({
            endpoint: "https://hooks.example.com/webhook",
            headers: { "X-Custom": "value" },
        });

        await t.dispatch(createTask());

        expect(fetchSpy).toHaveBeenCalledTimes(1);
        const [url, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("https://hooks.example.com/webhook");
        expect(options.method).toBe("POST");
        expect((options.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
        expect((options.headers as Record<string, string>)["X-Custom"]).toBe("value");
        const body = JSON.parse(options.body as string) as GeneratedTask;
        expect(body.taskId).toBe("task-001");
        expect(body.severity).toBe("CRITICAL");
        expect(body.sourceLog.traceId).toBe("t-1");
        expect(body.actionType).toBe("SYSTEM_NOTIFICATION");
    });

    it("returns success on HTTP 200", async () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        const result = await t.dispatch(createTask());

        expect(result.success).toBe(true);
        expect(result.transportName).toBe("http_webhook");
        expect(result.error).toBeUndefined();
    });

    it("returns success=false on HTTP 500", async () => {
        fetchSpy.mockResolvedValue({ ok: false, status: 500 });
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        const result = await t.dispatch(createTask());

        expect(result.success).toBe(false);
        expect(result.error).toContain("500");
    });

    it("returns success=false on HTTP 429", async () => {
        fetchSpy.mockResolvedValue({ ok: false, status: 429 });
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        const result = await t.dispatch(createTask());

        expect(result.success).toBe(false);
        expect(result.error).toContain("429");
    });

    it("throws on network error", async () => {
        fetchSpy.mockRejectedValue(new Error("ECONNREFUSED"));
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });

        await expect(t.dispatch(createTask())).rejects.toThrow("ECONNREFUSED");
    });

    it("uses custom method (PUT)", async () => {
        const t = new HttpWebhookTransport({
            endpoint: "https://example.com/hook",
            method: "PUT",
        });
        await t.dispatch(createTask());

        const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect(options.method).toBe("PUT");
    });

    it("user headers override defaults", async () => {
        const t = new HttpWebhookTransport({
            endpoint: "https://example.com/hook",
            headers: { "Content-Type": "text/plain" },
        });
        await t.dispatch(createTask());

        const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
        expect((options.headers as Record<string, string>)["Content-Type"]).toBe("text/plain");
    });
});

// =========================================================================
// close
// =========================================================================

describe("HttpWebhookTransport: close", () => {
    let fetchSpy: ReturnType<typeof vi.fn>;
    const originalFetch = globalThis.fetch;

    beforeEach(() => {
        fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it("close resolves without error", async () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        await expect(t.close()).resolves.toBeUndefined();
    });

    it("dispatch after close returns closed error and does not fetch", async () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        await t.close();

        const result = await t.dispatch(createTask());

        expect(result.success).toBe(false);
        expect(result.error).toContain("closed");
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("double close does not throw", async () => {
        const t = new HttpWebhookTransport({ endpoint: "https://example.com/hook" });
        await t.close();
        await expect(t.close()).resolves.toBeUndefined();
    });
});
