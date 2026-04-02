import { describe, it, expect } from "vitest";
import { EventDetector } from "../../../src/core/detection/event-detector";
import {
    createTestLog,
    createSecurityLog,
    createCriticalLog,
    createComplianceLog,
} from "../../helpers/fixtures";

describe("EventDetector", () => {
    const detector = new EventDetector();

    describe("critical failure detection", () => {
        it("detects isCritical logs as SYSTEM_CRITICAL_FAILURE", () => {
            const log = createCriticalLog();
            const result = detector.detect(log);

            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
            expect(result!.priority).toBe("HIGH");
            expect(result!.payload).toEqual({
                component: "db-service:connection-pool",
                errorDetails: "Database connection pool exhausted",
            });
        });

        it("detects critical even if type is not SYSTEM", () => {
            const log = createTestLog({ isCritical: true, type: "INFRA", message: "Disk failure" });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        });

        it("detects critical AI_AGENT logs (exception to AI skip rule)", () => {
            const log = createTestLog({
                isCritical: true,
                origin: "AI_AGENT",
                message: "Agent crash",
            });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
        });
    });

    describe("security intrusion detection", () => {
        it("detects SECURITY type with level >= 5", () => {
            const log = createSecurityLog({ level: 5 });
            const result = detector.detect(log);

            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("SECURITY_INTRUSION_DETECTED");
            expect(result!.priority).toBe("HIGH");
        });

        it("detects SECURITY type with level 6", () => {
            const log = createSecurityLog({ level: 6 });
            const result = detector.detect(log);
            expect(result!.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        });

        it("does NOT detect SECURITY type with level < 5", () => {
            const log = createSecurityLog({ level: 4 });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });

        it("extracts IP from tags", () => {
            const log = createSecurityLog({
                tags: [{ key: "ip", category: "10.0.0.1" }],
            });
            const result = detector.detect(log);
            expect(result!.payload).toHaveProperty("ip", "10.0.0.1");
        });

        it("defaults IP to 0.0.0.0 when not in tags (empty array)", () => {
            const log = createSecurityLog({ tags: [] });
            const result = detector.detect(log);
            expect(result!.payload).toHaveProperty("ip", "0.0.0.0");
        });

        it("defaults IP to 0.0.0.0 when tags have entries but no 'ip' key", () => {
            const log = createSecurityLog({
                tags: [{ key: "region", category: "ap-northeast-1" }, { key: "env", category: "prod" }],
            });
            const result = detector.detect(log);
            expect(result!.payload).toHaveProperty("ip", "0.0.0.0");
        });
    });

    describe("compliance violation detection", () => {
        it("detects COMPLIANCE type with 'violation' in message", () => {
            const log = createComplianceLog();
            const result = detector.detect(log);

            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("COMPLIANCE_VIOLATION");
        });

        it("is case-insensitive for 'violation'", () => {
            const log = createComplianceLog({ message: "VIOLATION detected" });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
        });

        it("does NOT detect COMPLIANCE without 'violation' keyword", () => {
            const log = createComplianceLog({ message: "Audit complete, no issues" });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });

        it("includes actorId and resourceIds in payload", () => {
            const log = createComplianceLog({
                actorId: "user-789",
                resourceIds: ["doc-abc"],
            });
            const result = detector.detect(log);
            expect(result!.payload).toEqual({
                ruleId: "AUTO-DETECT-001",
                documentId: "doc-abc",
                userId: "user-789",
            });
        });
    });

    describe("SLA violation detection", () => {
        it("detects SLA type with level >= 4", () => {
            const log = createTestLog({ type: "SLA", level: 4, message: "Response time exceeded" });
            const result = detector.detect(log);

            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
            expect(result!.priority).toBe("MEDIUM");
        });

        it("does NOT detect SLA with level < 4", () => {
            const log = createTestLog({ type: "SLA", level: 3, message: "Minor latency" });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });
    });

    describe("AI_AGENT loop prevention", () => {
        it("skips non-critical AI_AGENT logs", () => {
            const log = createTestLog({
                origin: "AI_AGENT",
                type: "SECURITY",
                level: 5,
                message: "Agent report",
            });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });

        it("does NOT skip critical AI_AGENT logs", () => {
            const log = createTestLog({
                origin: "AI_AGENT",
                isCritical: true,
                message: "Agent critical failure",
            });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
        });
    });

    describe("AI_ACTION_REQUIRED detection", () => {
        it("detects AI_ACTION_REQUIRED with SECURITY type level=4 → AI_ANALYZE", () => {
            // level=4 (not >=5) to avoid matching SECURITY_INTRUSION_DETECTED first
            const log = createTestLog({
                type: "SECURITY",
                level: 4,
                triggerAgent: true,
                message: "AI analysis needed",
            });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("AI_ACTION_REQUIRED");
            expect(result!.priority).toBe("MEDIUM");
            expect(result!.payload.suggestedTask).toBe("AI_ANALYZE");
        });

        it("detects AI_ACTION_REQUIRED with non-SECURITY type → SYSTEM_NOTIFICATION", () => {
            const log = createTestLog({
                type: "SYSTEM",
                level: 4,
                triggerAgent: true,
                message: "AI notification needed",
            });
            const result = detector.detect(log);
            expect(result).not.toBeNull();
            expect(result!.eventName).toBe("AI_ACTION_REQUIRED");
            expect(result!.priority).toBe("MEDIUM");
            expect(result!.payload.suggestedTask).toBe("SYSTEM_NOTIFICATION");
        });

        it("does not detect AI_ACTION_REQUIRED when triggerAgent=false", () => {
            const log = createTestLog({
                type: "SYSTEM",
                level: 5,
                triggerAgent: false,
                message: "No trigger",
            });
            const result = detector.detect(log);
            // triggerAgent=false かつ他の条件にもマッチしない
            expect(result).toBeNull();
        });

        it("does not detect AI_ACTION_REQUIRED when level < 4", () => {
            const log = createTestLog({
                type: "SYSTEM",
                level: 3,
                triggerAgent: true,
                message: "Low level trigger",
            });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });
    });

    describe("no detection", () => {
        it("returns null for normal SYSTEM log", () => {
            const log = createTestLog();
            const result = detector.detect(log);
            expect(result).toBeNull();
        });

        it("returns null for DEBUG log", () => {
            const log = createTestLog({ type: "DEBUG", level: 1, message: "debug info" });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });

        it("returns null for low-level INFRA log", () => {
            const log = createTestLog({ type: "INFRA", level: 2, message: "health check ok" });
            const result = detector.detect(log);
            expect(result).toBeNull();
        });
    });
});
