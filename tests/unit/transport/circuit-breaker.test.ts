import { describe, it, expect, vi, beforeEach } from "vitest";
import { CircuitBreaker } from "../../../src/transport/circuit-breaker";

describe("CircuitBreaker (R-4)", () => {
    let cb: CircuitBreaker;

    beforeEach(() => {
        cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000 });
    });

    it("starts in closed state", () => {
        expect(cb.getState()).toBe("closed");
        expect(cb.canExecute()).toBe(true);
    });

    it("remains closed below failure threshold", () => {
        cb.onFailure();
        cb.onFailure();
        expect(cb.getState()).toBe("closed");
        expect(cb.canExecute()).toBe(true);
    });

    it("opens after reaching failure threshold", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onFailure();
        expect(cb.getState()).toBe("open");
        expect(cb.canExecute()).toBe(false);
    });

    it("resets failure count on success", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onSuccess();
        expect(cb.getState()).toBe("closed");
        cb.onFailure(); // only 1 failure after reset
        expect(cb.getState()).toBe("closed");
    });

    it("transitions to half-open after cooldown", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onFailure();
        expect(cb.getState()).toBe("open");

        // Simulate cooldown elapsed
        vi.useFakeTimers();
        vi.advanceTimersByTime(1001);
        expect(cb.getState()).toBe("half-open");
        expect(cb.canExecute()).toBe(true);
        vi.useRealTimers();
    });

    it("returns to closed on success in half-open state", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onFailure();

        vi.useFakeTimers();
        vi.advanceTimersByTime(1001);
        expect(cb.getState()).toBe("half-open");

        cb.onSuccess();
        expect(cb.getState()).toBe("closed");
        expect(cb.canExecute()).toBe(true);
        vi.useRealTimers();
    });

    it("returns to open on failure in half-open state", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onFailure();

        vi.useFakeTimers();
        vi.advanceTimersByTime(1001);
        expect(cb.getState()).toBe("half-open");

        cb.onFailure();
        expect(cb.getState()).toBe("open");
        expect(cb.canExecute()).toBe(false);
        vi.useRealTimers();
    });

    it("reset() returns to initial state", () => {
        cb.onFailure();
        cb.onFailure();
        cb.onFailure();
        expect(cb.getState()).toBe("open");

        cb.reset();
        expect(cb.getState()).toBe("closed");
        expect(cb.canExecute()).toBe(true);
    });

    it("uses default config when no config provided", () => {
        const defaultCb = new CircuitBreaker();
        // Default threshold is 5
        for (let i = 0; i < 4; i++) defaultCb.onFailure();
        expect(defaultCb.getState()).toBe("closed");
        defaultCb.onFailure();
        expect(defaultCb.getState()).toBe("open");
    });
});
