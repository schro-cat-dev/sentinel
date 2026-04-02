import { describe, it, expect, vi } from "vitest";
import { createTaskTransportsFromConfig } from "../../../src/transport/task-transport-factory";
import { ConsoleTaskTransport } from "../../../src/transport/console-task-transport";
import { HttpWebhookTransport } from "../../../src/transport/http-webhook-transport";
import type { TaskTransportConfig } from "../../../src/configs/sentinel-config";

describe("createTaskTransportsFromConfig", () => {
    it("creates HttpWebhookTransport for type http_webhook", () => {
        const configs: TaskTransportConfig[] = [{
            name: "slack",
            type: "http_webhook",
            enabled: true,
            endpoint: "https://hooks.slack.com/services/xxx",
        }];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(1);
        expect(transports[0]).toBeInstanceOf(HttpWebhookTransport);
        expect(transports[0].name).toBe("slack");
    });

    it("creates ConsoleTaskTransport for type console", () => {
        const configs: TaskTransportConfig[] = [{
            name: "debug",
            type: "console",
            enabled: true,
        }];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(1);
        expect(transports[0]).toBeInstanceOf(ConsoleTaskTransport);
        expect(transports[0].name).toBe("debug");
    });

    it("skips type custom entries", () => {
        const configs: TaskTransportConfig[] = [{
            name: "user-provided",
            type: "custom",
            enabled: true,
        }];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(0);
    });

    it("skips entries with undefined type", () => {
        const configs: TaskTransportConfig[] = [{
            name: "no-type",
            enabled: true,
        }];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(0);
    });

    it("filters out enabled: false entries", () => {
        const configs: TaskTransportConfig[] = [
            { name: "active", type: "console", enabled: true },
            { name: "disabled", type: "console", enabled: false },
        ];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(1);
        expect(transports[0].name).toBe("active");
    });

    it("handles empty array", () => {
        expect(createTaskTransportsFromConfig([])).toEqual([]);
    });

    it("handles mixed types", () => {
        const configs: TaskTransportConfig[] = [
            { name: "webhook", type: "http_webhook", enabled: true, endpoint: "https://example.com/hook" },
            { name: "debug", type: "console", enabled: true },
            { name: "user", type: "custom", enabled: true },
            { name: "off", type: "console", enabled: false },
        ];

        const transports = createTaskTransportsFromConfig(configs);

        expect(transports).toHaveLength(2);
        expect(transports[0]).toBeInstanceOf(HttpWebhookTransport);
        expect(transports[1]).toBeInstanceOf(ConsoleTaskTransport);
    });

    it("passes headers to HttpWebhookTransport (verified via dispatch)", async () => {
        const originalFetch = globalThis.fetch;
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        try {
            const configs: TaskTransportConfig[] = [{
                name: "with-headers",
                type: "http_webhook",
                enabled: true,
                endpoint: "https://example.com/hook",
                headers: { Authorization: "Bearer token123" },
            }];

            const transports = createTaskTransportsFromConfig(configs);
            expect(transports).toHaveLength(1);

            // dispatch して fetch に渡されるヘッダーを検証
            const task = { taskId: "t1" } as unknown as import("../../../src/types/task").GeneratedTask;
            await transports[0].dispatch(task);

            const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
            expect((options.headers as Record<string, string>).Authorization).toBe("Bearer token123");
            expect((options.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("passes method to HttpWebhookTransport (verified via dispatch)", async () => {
        const originalFetch = globalThis.fetch;
        const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        globalThis.fetch = fetchSpy;

        try {
            const configs: TaskTransportConfig[] = [{
                name: "put-hook",
                type: "http_webhook",
                enabled: true,
                endpoint: "https://example.com/hook",
                method: "PUT",
            }];

            const transports = createTaskTransportsFromConfig(configs);
            const task = { taskId: "t1" } as unknown as import("../../../src/types/task").GeneratedTask;
            await transports[0].dispatch(task);

            const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
            expect(options.method).toBe("PUT");
        } finally {
            globalThis.fetch = originalFetch;
        }
    });

    it("passes allow_insecure to HttpWebhookTransport", () => {
        const configs: TaskTransportConfig[] = [{
            name: "dev-hook",
            type: "http_webhook",
            enabled: true,
            endpoint: "http://localhost:3000/hook",
            allow_insecure: true,
        }];

        // allowInsecure=true なので http://localhost は許可される
        const transports = createTaskTransportsFromConfig(configs);
        expect(transports).toHaveLength(1);
        expect(transports[0].name).toBe("dev-hook");
    });

    it("throws when http_webhook endpoint fails SSRF without allow_insecure", () => {
        const configs: TaskTransportConfig[] = [{
            name: "private-hook",
            type: "http_webhook",
            enabled: true,
            endpoint: "https://192.168.1.1/hook",
        }];

        expect(() => createTaskTransportsFromConfig(configs)).toThrow();
    });

    it("handles all entries disabled (returns empty array)", () => {
        const configs: TaskTransportConfig[] = [
            { name: "a", type: "console", enabled: false },
            { name: "b", type: "http_webhook", enabled: false, endpoint: "https://example.com" },
        ];

        expect(createTaskTransportsFromConfig(configs)).toEqual([]);
    });
});
