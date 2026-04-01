/**
 * ConsoleAuditSink Tests — Gap 2 remediation
 * serializeForAudit() がパイプラインに接続されることを検証
 */
import { describe, it, expect, vi } from "vitest";
import { ConsoleAuditSink } from "../../../src/error-routing/sinks/console-audit-sink";
import { ErrorRouter } from "../../../src/error-routing/error-router";
import type { ClassifiedError } from "../../../src/error-routing/types";

describe("ConsoleAuditSink", () => {
    it("send() outputs structured JSON to console.error", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sink = new ConsoleAuditSink();

        const error: ClassifiedError = {
            kind: "TransportTimeout",
            detailKind: "transport.dual",
            code: "TRANSPORT_TIMEOUT",
            message: "Transport timeout after 30000ms",
            severity: "WARNING",
            meta: { traceId: "t-1", context: {} },
        };

        await sink.send(error);

        expect(stderrSpy).toHaveBeenCalled();
        const output = stderrSpy.mock.calls[0][0] as string;
        expect(output).toContain("TRANSPORT_TIMEOUT");
        expect(output).toContain("t-1");
        stderrSpy.mockRestore();
    });

    it("PII in context is masked", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sink = new ConsoleAuditSink();

        const error: ClassifiedError = {
            kind: "Test",
            detailKind: "test",
            code: "TEST",
            message: "test",
            severity: "INFO",
            meta: { traceId: "t-1", context: { email: "alice@secret.com" } },
        };

        await sink.send(error);

        const output = stderrSpy.mock.calls[0][0] as string;
        expect(output).not.toContain("alice@secret.com");
        stderrSpy.mockRestore();
    });

    it("ErrorRouter + ConsoleAuditSink E2E", async () => {
        const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const sink = new ConsoleAuditSink();
        const router = new ErrorRouter({
            enabled: true,
            sinks: { audit: sink },
        });

        await router.route(new Error("connection refused"), "transport.dual", "trace-abc");

        expect(stderrSpy).toHaveBeenCalled();
        const output = stderrSpy.mock.calls[0][0] as string;
        expect(output).toContain("trace-abc");
        stderrSpy.mockRestore();
    });
});
