import { describe, it, expect } from "vitest";
import { ErrorClassifier } from "../../../src/error-routing/error-classifier";

describe("ErrorClassifier", () => {
    const classifier = new ErrorClassifier();

    it("classifies transport timeout as WARNING", () => {
        const result = classifier.classify({
            error: new Error("Transport timeout after 30000ms"),
            context: "transport.dual",
            traceId: "t-1",
        });
        expect(result.kind).toBe("TransportTimeout");
        expect(result.severity).toBe("WARNING");
        expect(result.meta.traceId).toBe("t-1");
    });

    it("classifies connection refused as CRITICAL", () => {
        const result = classifier.classify({
            error: new Error("connection refused"),
            context: "transport.dual",
        });
        expect(result.kind).toBe("TransportConnectionRefused");
        expect(result.severity).toBe("CRITICAL");
    });

    it("classifies handler exception as WARNING", () => {
        const result = classifier.classify({
            error: new Error("handler crashed"),
            context: "task.dispatch",
        });
        expect(result.kind).toBe("HandlerException");
        expect(result.severity).toBe("WARNING");
    });

    it("classifies validation error as INFO", () => {
        const result = classifier.classify({
            error: new Error("validation(message): is required"),
            context: "callback",
        });
        expect(result.kind).toBe("ValidationFailure");
        expect(result.severity).toBe("INFO");
    });

    it("classifies unknown error as WARNING", () => {
        const result = classifier.classify({
            error: new Error("something unexpected"),
            context: "callback",
        });
        expect(result.kind).toBe("Unknown");
        expect(result.severity).toBe("WARNING");
    });

    it("accepts custom severity config", () => {
        const custom = new ErrorClassifier({
            CRITICAL: ["Unknown"],
            WARNING: [],
        });
        const result = custom.classify({
            error: new Error("anything"),
            context: "callback",
        });
        expect(result.severity).toBe("CRITICAL");
    });

    it("handles null/undefined error message safely", () => {
        const result = classifier.classify({
            error: { message: undefined } as unknown as Error,
            context: "callback",
        });
        expect(result.kind).toBe("Unknown");
    });

    it("handles non-Error object safely", () => {
        const result = classifier.classify({
            error: "string error" as unknown as Error,
            context: "callback",
        });
        expect(result.kind).toBe("Unknown");
        expect(result.message).toContain("string error");
    });

    it("propagates traceId/layer/operation to meta", () => {
        const result = classifier.classify({
            error: new Error("test"),
            context: "engine.mask",
            traceId: "tr-abc",
            layer: "security",
            operation: "mask",
        });
        expect(result.meta.traceId).toBe("tr-abc");
        expect(result.meta.layer).toBe("security");
        expect(result.meta.operation).toBe("mask");
    });

    it("classifySeverity falls back to WARNING for kind not in any list", () => {
        // Custom config with empty lists → "Unknown" kind hits default WARNING
        const custom = new ErrorClassifier({ CRITICAL: [], WARNING: [] });
        const result = custom.classify({
            error: new Error("random error"),
            context: "callback",
        });
        expect(result.kind).toBe("Unknown");
        expect(result.severity).toBe("WARNING");
    });

    it("safeMessage catch branch for exotic error that throws on String()", () => {
        const exotic = {
            get message(): string { throw new Error("getter throws"); },
            // toString also throws
            toString(): string { throw new Error("toString throws"); },
        };
        const result = classifier.classify({
            error: exotic as unknown as Error,
            context: "callback",
        });
        // safeMessage should catch and return "unknown error"
        expect(result.message).toBe("unknown error");
    });

    it("classification itself throwing returns ClassificationError", () => {
        // Force classify to fail by passing input that causes context.startsWith to throw
        const poisoned = {
            error: new Error("test"),
            get context(): string { throw new Error("poison"); },
        };
        const result = classifier.classify(poisoned as never);
        expect(result.kind).toBe("ClassificationError");
    });
});
