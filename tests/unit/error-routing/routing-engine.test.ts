import { describe, it, expect } from "vitest";
import { RoutingEngine } from "../../../src/error-routing/routing-engine";
import type { ClassifiedError } from "../../../src/error-routing/types";

const makeError = (kind: string, severity: "CRITICAL" | "WARNING" | "INFO"): ClassifiedError => ({
    kind, severity, detailKind: "", code: "", message: "test",
    meta: { traceId: "t", context: {} },
});

describe("RoutingEngine", () => {
    it("CRITICAL → task + notification + audit", () => {
        const engine = new RoutingEngine();
        const decisions = engine.evaluate(makeError("EngineInternalError", "CRITICAL"));
        expect(decisions.some((d) => d.destination === "task")).toBe(true);
        expect(decisions.some((d) => d.destination === "notification")).toBe(true);
        expect(decisions.some((d) => d.destination === "audit_sink")).toBe(true);
    });

    it("WARNING + Transport → dead_letter + audit", () => {
        const engine = new RoutingEngine();
        const decisions = engine.evaluate(makeError("TransportTimeout", "WARNING"));
        expect(decisions.some((d) => d.destination === "dead_letter")).toBe(true);
        expect(decisions.some((d) => d.destination === "audit_sink")).toBe(true);
    });

    it("WARNING + Handler → ai_agent + audit", () => {
        const engine = new RoutingEngine();
        const decisions = engine.evaluate(makeError("HandlerException", "WARNING"));
        expect(decisions.some((d) => d.destination === "ai_agent")).toBe(true);
    });

    it("INFO → log only", () => {
        const engine = new RoutingEngine();
        const decisions = engine.evaluate(makeError("ValidationFailure", "INFO"));
        expect(decisions).toHaveLength(1);
        expect(decisions[0].destination).toBe("log");
    });

    it("custom rules override defaults", () => {
        const engine = new RoutingEngine([
            { match: { severity: "CRITICAL" }, decisions: [{ destination: "log", action: "record", priority: 5 }] },
        ]);
        const decisions = engine.evaluate(makeError("anything", "CRITICAL"));
        expect(decisions).toHaveLength(1);
        expect(decisions[0].destination).toBe("log");
    });

    it("first-match-wins", () => {
        const engine = new RoutingEngine([
            { match: { severity: "WARNING" }, decisions: [{ destination: "log", action: "record", priority: 5 }] },
            { match: { severity: "WARNING", kindPattern: /Handler/ }, decisions: [{ destination: "task", action: "escalate", priority: 1 }] },
        ]);
        const decisions = engine.evaluate(makeError("HandlerException", "WARNING"));
        // First rule matches WARNING → log, second never evaluated
        expect(decisions[0].destination).toBe("log");
    });

    it("no rule match → default (log)", () => {
        const engine = new RoutingEngine([
            { match: { severity: "CRITICAL" }, decisions: [] },
        ]);
        const decisions = engine.evaluate(makeError("Something", "INFO"));
        expect(decisions).toHaveLength(1);
        expect(decisions[0].destination).toBe("log");
    });

    it("kindPattern regex matching works", () => {
        const engine = new RoutingEngine([
            { match: { severity: "WARNING", kindPattern: /^Transport/ }, decisions: [{ destination: "dead_letter", action: "retry", priority: 3 }] },
        ]);
        const d1 = engine.evaluate(makeError("TransportTimeout", "WARNING"));
        expect(d1[0].destination).toBe("dead_letter");

        const d2 = engine.evaluate(makeError("HandlerTimeout", "WARNING"));
        expect(d2[0].destination).toBe("log"); // no match → default
    });

    it("empty decisions array means no action", () => {
        const engine = new RoutingEngine([
            { match: { severity: "INFO" }, decisions: [] },
        ]);
        const decisions = engine.evaluate(makeError("test", "INFO"));
        expect(decisions).toHaveLength(0);
    });
});
