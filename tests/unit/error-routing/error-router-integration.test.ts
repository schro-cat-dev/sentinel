/**
 * ErrorRouter Integration Tests — Gap 1 remediation
 * task/notification/ai_agent destination の実装検証
 */
import { describe, it, expect, vi } from "vitest";
import { ErrorRouter } from "../../../src/error-routing/error-router";
import type { AuditSink, ErrorRoutingConfig } from "../../../src/error-routing/types";

describe("ErrorRouter: task destination", () => {
    it("CRITICAL error generates a task via onTaskRequest", async () => {
        const onTaskRequest = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest,
        });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(onTaskRequest).toHaveBeenCalledWith(
            expect.objectContaining({
                actionType: "ESCALATE",
                eventName: "ERROR_ESCALATION",
            }),
        );
    });

    it("ai_agent destination generates AI_ANALYZE task", async () => {
        const onTaskRequest = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest,
            rules: [{
                match: { severity: "WARNING", kindPattern: /Handler/ },
                decisions: [{ destination: "ai_agent", action: "auto_remediate", priority: 2 }],
            }],
        });

        await router.route(new Error("handler crashed"), "task.dispatch");

        expect(onTaskRequest).toHaveBeenCalledWith(
            expect.objectContaining({ actionType: "AI_ANALYZE" }),
        );
    });
});

describe("ErrorRouter: notification destination", () => {
    it("notification destination calls onNotification", async () => {
        const onNotification = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onNotification,
        });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(onNotification).toHaveBeenCalledWith(
            expect.objectContaining({ kind: "TransportConnectionRefused" }),
            expect.objectContaining({ action: "escalate" }),
        );
    });

    it("sink not configured → destination silently skipped", async () => {
        // No sinks, no onTaskRequest, no onNotification
        const router = new ErrorRouter({ enabled: true });

        // Should not throw
        await expect(router.route(new Error("connection refused"), "transport.dual")).resolves.toBeUndefined();
    });

    it("task generation failure does not stop other destinations", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sink: AuditSink = { send: vi.fn().mockResolvedValue(undefined) };
        const router = new ErrorRouter({
            enabled: true,
            sinks: { audit: sink },
            onTaskRequest: () => { throw new Error("task gen failed"); },
        });

        await router.route(new Error("connection refused"), "transport.dual");

        // audit_sink should still be called despite task failure
        expect(sink.send).toHaveBeenCalled();
        stderrSpy.mockRestore();
    });

    it("all destinations execute concurrently", async () => {
        const order: string[] = [];
        const sink: AuditSink = {
            send: vi.fn().mockImplementation(async () => { order.push("audit"); }),
        };
        const router = new ErrorRouter({
            enabled: true,
            sinks: { audit: sink },
            onTaskRequest: () => { order.push("task"); },
            onNotification: () => { order.push("notify"); },
        });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(order).toContain("task");
        expect(order).toContain("notify");
        expect(order).toContain("audit");
    });
});
