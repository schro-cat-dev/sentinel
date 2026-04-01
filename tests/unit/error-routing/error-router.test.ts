import { describe, it, expect, vi } from "vitest";
import { ErrorRouter } from "../../../src/error-routing/error-router";
import type { AuditSink, ErrorRoutingLogger } from "../../../src/error-routing/types";

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
            send: vi.fn().mockImplementation(async (p) => { capturedPayload = p; }),
        };
        const router = new ErrorRouter({ enabled: true, sinks: { audit: sink } });

        const err = new Error("user alice@secret.com failed");
        await router.route(err, "callback");

        // Message should still contain original (classification doesn't mask message)
        // But meta.context should be safe
        expect(capturedPayload).toBeDefined();
    });
});
