import { describe, it, expect } from "vitest";
import { SentinelError } from "../../../src/errors/sentinel-error";

describe("SentinelError (O-4)", () => {
    it("has name 'SentinelError'", () => {
        const err = new SentinelError("transport", "send", "connection refused");
        expect(err.name).toBe("SentinelError");
    });

    it("is instanceof Error", () => {
        const err = new SentinelError("transport", "send", "timeout");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(SentinelError);
    });

    it("carries layer and operation", () => {
        const err = new SentinelError("pipeline", "normalize", "invalid log");
        expect(err.layer).toBe("pipeline");
        expect(err.operation).toBe("normalize");
        expect(err.message).toBe("invalid log");
    });

    it("optionally carries a cause", () => {
        const cause = new Error("root cause");
        const err = new SentinelError("transport", "send", "wrapped", cause);
        expect(err.cause).toBe(cause);
    });

    it("works without cause", () => {
        const err = new SentinelError("task", "dispatch", "handler failed");
        expect(err.cause).toBeUndefined();
    });

    it("has proper stack trace with file and line info", () => {
        const err = new SentinelError("detection", "detect", "rule error");
        expect(err.stack).toBeDefined();
        // Stack trace must contain class name AND at least one "at" frame with file reference
        expect(err.stack).toContain("SentinelError");
        expect(err.stack).toMatch(/at\s+/); // "at <function/location>"
        expect(err.stack).toMatch(/\.ts:|\.js:/); // file reference with line number
    });
});
