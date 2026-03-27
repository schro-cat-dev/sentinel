import { describe, it, expect } from "vitest";
import { SeverityClassifier } from "../../../src/core/task/severity-classifier";
import { DetectionResult, SystemEventName } from "../../../src/types/event";
import { createTestLog, createCriticalLog, createSecurityLog } from "../../helpers/fixtures";

describe("SeverityClassifier", () => {
    const classifier = new SeverityClassifier();

    const makeDetection = (
        eventName: SystemEventName,
        priority: "HIGH" | "MEDIUM" | "LOW" = "HIGH",
    ): DetectionResult<SystemEventName> => ({
        eventName,
        priority,
        payload: {} as any,
    });

    describe("isCritical override", () => {
        it("always returns CRITICAL for isCritical logs", () => {
            const log = createCriticalLog();
            const result = classifier.classify(
                makeDetection("SYSTEM_CRITICAL_FAILURE"),
                log,
            );
            expect(result).toBe("CRITICAL");
        });

        it("returns CRITICAL even for low-priority detection when isCritical", () => {
            const log = createCriticalLog();
            const result = classifier.classify(
                makeDetection("AI_ACTION_REQUIRED", "LOW"),
                log,
            );
            expect(result).toBe("CRITICAL");
        });
    });

    describe("SECURITY_INTRUSION_DETECTED", () => {
        it("returns CRITICAL for level 6", () => {
            const log = createSecurityLog({ level: 6 });
            const result = classifier.classify(
                makeDetection("SECURITY_INTRUSION_DETECTED"),
                log,
            );
            expect(result).toBe("CRITICAL");
        });

        it("returns HIGH for level 5", () => {
            const log = createSecurityLog({ level: 5 });
            const result = classifier.classify(
                makeDetection("SECURITY_INTRUSION_DETECTED"),
                log,
            );
            expect(result).toBe("HIGH");
        });
    });

    describe("SYSTEM_CRITICAL_FAILURE", () => {
        it("returns CRITICAL for HIGH priority detection", () => {
            const log = createTestLog({ level: 4 });
            const result = classifier.classify(
                makeDetection("SYSTEM_CRITICAL_FAILURE", "HIGH"),
                log,
            );
            expect(result).toBe("CRITICAL");
        });

        it("returns HIGH for MEDIUM priority detection", () => {
            const log = createTestLog({ level: 4 });
            const result = classifier.classify(
                makeDetection("SYSTEM_CRITICAL_FAILURE", "MEDIUM"),
                log,
            );
            expect(result).toBe("HIGH");
        });
    });

    describe("COMPLIANCE_VIOLATION", () => {
        it("always returns HIGH", () => {
            const log = createTestLog({ type: "COMPLIANCE", level: 3 });
            const result = classifier.classify(
                makeDetection("COMPLIANCE_VIOLATION"),
                log,
            );
            expect(result).toBe("HIGH");
        });
    });

    describe("AI_ACTION_REQUIRED", () => {
        it("returns MEDIUM", () => {
            const log = createTestLog();
            const result = classifier.classify(
                makeDetection("AI_ACTION_REQUIRED"),
                log,
            );
            expect(result).toBe("MEDIUM");
        });
    });

    describe("log level fallback", () => {
        it("maps level 6 to CRITICAL", () => {
            const log = createTestLog({ level: 6 });
            const result = classifier.classify(
                { eventName: "unknown" as any, priority: "LOW", payload: {} as any },
                log,
            );
            expect(result).toBe("CRITICAL");
        });

        it("maps level 5 to HIGH", () => {
            const log = createTestLog({ level: 5 });
            const result = classifier.classify(
                { eventName: "unknown" as any, priority: "LOW", payload: {} as any },
                log,
            );
            expect(result).toBe("HIGH");
        });

        it("maps level 4 to MEDIUM", () => {
            const log = createTestLog({ level: 4 });
            const result = classifier.classify(
                { eventName: "unknown" as any, priority: "LOW", payload: {} as any },
                log,
            );
            expect(result).toBe("MEDIUM");
        });

        it("maps level 3 to LOW", () => {
            const log = createTestLog({ level: 3 });
            const result = classifier.classify(
                { eventName: "unknown" as any, priority: "LOW", payload: {} as any },
                log,
            );
            expect(result).toBe("LOW");
        });

        it("maps level 1-2 to INFO", () => {
            const log = createTestLog({ level: 1 });
            const result = classifier.classify(
                { eventName: "unknown" as any, priority: "LOW", payload: {} as any },
                log,
            );
            expect(result).toBe("INFO");
        });
    });
});
