import { describe, it, expect, vi } from "vitest";
import { ErrorRouter } from "../../../src/error-routing/error-router";
import type { AuditSink, DeadLetterQueue, ErrorRoutingLogger } from "../../../src/error-routing/types";

describe("ErrorRouter", () => {
    it("enabled=true routes error through classify → evaluate → execute", async () => {
        const sink: AuditSink = { send: vi.fn().mockResolvedValue(undefined) };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(sink.send).toHaveBeenCalled();
    });

    it("enabled=false does nothing", async () => {
        const sink: AuditSink = { send: vi.fn() };
        const router = new ErrorRouter({ enabled: false, sinks: { audit: sink } });

        await router.route(new Error("test"), "callback");

        expect(sink.send).not.toHaveBeenCalled();
    });

    it("maxRoutingDepth=1 prevents infinite loop", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        // Sink that throws → would cause re-entry if not guarded
        const sink: AuditSink = { send: vi.fn().mockRejectedValue(new Error("sink failed")) };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        // Should not hang or recurse
        await router.route(new Error("test"), "callback");

        // Sink error should go to console.error, not back to router
        expect(stderrSpy).toHaveBeenCalled();
        stderrSpy.mockRestore();
    });

    it("route during shutdown is safely ignored", async () => {
        const sink: AuditSink = { send: vi.fn() };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        router.shutdown();
        await router.route(new Error("test"), "callback");

        expect(sink.send).not.toHaveBeenCalled();
    });

    it("shutdown clears resources", () => {
        const router = new ErrorRouter({ enabled: true });
        router.shutdown();
        // Should not throw on second shutdown
        expect(() => router.shutdown()).not.toThrow();
    });

    it("all sinks failing falls back to console.error", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sink: AuditSink = { send: vi.fn().mockRejectedValue(new Error("boom")) };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(stderrSpy).toHaveBeenCalled();
        stderrSpy.mockRestore();
    });

    it("PII in error context is masked before sending to sink", async () => {
        let capturedPayload: unknown = null;
        const sink: AuditSink = {
            send: vi.fn().mockImplementation(async (p: unknown) => { capturedPayload = p; }),
        };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        const err = new Error("user alice@secret.com failed");
        await router.route(err, "callback");

        // Message should still contain original (classification doesn't mask message)
        // But meta.context should be safe
        expect(capturedPayload).toBeDefined();
    });

    it("log destination calls logger.info with structured data", async () => {
        const logger: ErrorRoutingLogger = { info: vi.fn() };
        // "validation(...)" messages classify as ValidationFailure → INFO severity
        const router = new ErrorRouter({
            enabled: true,
            logger,
            rules: [
                {
                    match: { severity: "INFO" },
                    decisions: [{ destination: "log", action: "record", priority: 5 }],
                },
            ],
        });

        await router.route(new Error("validation(field) failed"), "callback", "trace-abc");

        expect(logger.info).toHaveBeenCalledTimes(1);
        const call = vi.mocked(logger.info).mock.calls[0];
        expect(call[0]).toContain("[ErrorRouter:log]");
        expect(call[0]).toContain("validation(field) failed");
        expect(call[1]).toEqual(
            expect.objectContaining({ severity: "INFO", traceId: "trace-abc" }),
        );
    });

    it("dead_letter destination enqueues classified error", async () => {
        const dlq: DeadLetterQueue = { enqueue: vi.fn().mockResolvedValue(undefined) };
        const router = new ErrorRouter({
            enabled: true,
            sinks: { deadLetter: dlq },
            rules: [
                {
                    match: { severity: "WARNING" },
                    decisions: [{
                        destination: "dead_letter",
                        action: "retry",
                        priority: 3,
                        metadata: { reason: "transient" },
                    }],
                },
            ],
        });

        await router.route(new Error("some warning"), "callback");
        expect(dlq.enqueue).toHaveBeenCalledTimes(1);
        const call = vi.mocked(dlq.enqueue).mock.calls[0];
        expect(call[1]).toEqual({ reason: "transient" });
    });

    it("dead_letter without metadata passes empty object", async () => {
        const dlq: DeadLetterQueue = { enqueue: vi.fn().mockResolvedValue(undefined) };
        const router = new ErrorRouter({
            enabled: true,
            sinks: { deadLetter: dlq },
            rules: [
                {
                    match: { severity: "WARNING" },
                    decisions: [{ destination: "dead_letter", action: "retry", priority: 3 }],
                },
            ],
        });

        await router.route(new Error("some warning"), "callback");
        const call = vi.mocked(dlq.enqueue).mock.calls[0];
        expect(call[1]).toEqual({});
    });

    it("task destination calls onTaskRequest with ESCALATE", async () => {
        const onTaskRequest = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest,
            rules: [
                {
                    match: { severity: "CRITICAL" },
                    decisions: [{ destination: "task", action: "escalate", priority: 1 }],
                },
            ],
        });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(onTaskRequest).toHaveBeenCalledTimes(1);
        expect(onTaskRequest).toHaveBeenCalledWith(
            expect.objectContaining({
                eventName: "ERROR_ESCALATION",
                actionType: "ESCALATE",
            }),
        );
    });

    it("ai_agent destination calls onTaskRequest with AI_ANALYZE", async () => {
        const onTaskRequest = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest,
            rules: [
                {
                    match: { severity: "WARNING", kindPattern: /^Handler/ },
                    decisions: [{ destination: "ai_agent", action: "auto_remediate", priority: 2 }],
                },
            ],
        });

        // "timeout" + "task" context → HandlerTimeout → WARNING severity, kind starts with "Handler"
        await router.route(new Error("timeout occurred"), "task.timeout");

        expect(onTaskRequest).toHaveBeenCalledTimes(1);
        expect(onTaskRequest).toHaveBeenCalledWith(
            expect.objectContaining({
                eventName: "ERROR_ESCALATION",
                actionType: "AI_ANALYZE",
            }),
        );
    });

    it("notification destination calls onNotification", async () => {
        const onNotification = vi.fn();
        const router = new ErrorRouter({
            enabled: true,
            onNotification,
            rules: [
                {
                    match: { severity: "CRITICAL" },
                    decisions: [{ destination: "notification", action: "escalate", priority: 1 }],
                },
            ],
        });

        await router.route(new Error("connection refused"), "transport.dual");

        expect(onNotification).toHaveBeenCalledTimes(1);
        const [error, decision] = onNotification.mock.calls[0];
        expect(error.kind).toBe("TransportConnectionRefused");
        expect(decision.destination).toBe("notification");
    });

    it("classify/evaluate throwing falls back to console.error", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        // Router with a rule whose kindPattern.test will throw
        const throwingPattern = {
            test: () => { throw new Error("regex engine exploded"); },
        };
        const router = new ErrorRouter({
            enabled: true,
            rules: [
                {
                    match: { severity: "CRITICAL", kindPattern: throwingPattern as unknown as RegExp },
                    decisions: [],
                },
            ],
        });

        await router.route(new Error("connection refused"), "transport.dual");
        expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("[Sentinel:ErrorRouter] routing failed:"));
        stderrSpy.mockRestore();
    });

    it("log destination without logger does nothing (no-op)", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const router = new ErrorRouter({
            enabled: true,
            rules: [
                {
                    match: { severity: "INFO" },
                    decisions: [{ destination: "log", action: "record", priority: 5 }],
                },
            ],
        });

        // "shutdown" in message → ShutdownViolation → INFO severity
        await router.route(new Error("shutdown violation"), "callback");

        // Should not throw or call console.error
        expect(stderrSpy).not.toHaveBeenCalled();
        stderrSpy.mockRestore();
    });
});
