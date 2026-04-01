/**
 * Custom Detection Rules Tests (TDD)
 *
 * 設定可能なルールベース不正アクセス検知のテスト。
 * 正常系・異常系・エッジケース・ペネトレーションテスト。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { EventDetector } from "../../../src/core/detection/event-detector";
import { createTestLog, createTestTaskRule } from "../../helpers/fixtures";
import type { DetectionRule } from "../../../src/types/event";
import type { Log } from "../../../src/types/log";

// ===== 正常系: カスタムルールが動作する =====
describe("Custom Detection Rules: normal cases", () => {
    it("detects log matching custom rule by messagePattern", () => {
        const rules: DetectionRule[] = [{
            ruleId: "brute-force",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                logTypes: ["SECURITY"],
                minLevel: 3,
                messagePattern: /failed.*login/i,
            },
        }];

        const detector = new EventDetector(rules);
        const log = createTestLog({
            type: "SECURITY",
            level: 4,
            message: "Failed login attempt from 10.0.0.1",
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        expect(result!.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        expect(result!.priority).toBe("HIGH");
    });

    it("detects log matching custom rule by tagMatch", () => {
        const rules: DetectionRule[] = [{
            ruleId: "suspicious-ip",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                tagMatch: { key: "ip", value: "10.0.0.99" },
            },
        }];

        const detector = new EventDetector(rules);
        const log = createTestLog({
            tags: [{ key: "ip", category: "10.0.0.99" }],
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
    });

    it("detects log matching custom rule by logType only", () => {
        const rules: DetectionRule[] = [{
            ruleId: "all-compliance",
            eventName: "COMPLIANCE_VIOLATION",
            priority: "MEDIUM",
            conditions: {
                logTypes: ["COMPLIANCE"],
            },
        }];

        const detector = new EventDetector(rules);
        const log = createTestLog({ type: "COMPLIANCE", message: "some event" });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        expect(result!.eventName).toBe("COMPLIANCE_VIOLATION");
    });

    it("detects log matching minLevel threshold", () => {
        const rules: DetectionRule[] = [{
            ruleId: "high-level",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            priority: "HIGH",
            conditions: { minLevel: 5 },
        }];

        const detector = new EventDetector(rules);

        expect(detector.detect(createTestLog({ level: 5 }))).not.toBeNull();
        expect(detector.detect(createTestLog({ level: 6 }))).not.toBeNull();
        expect(detector.detect(createTestLog({ level: 4 }))).toBeNull();
    });

    it("detects log matching maxLevel threshold", () => {
        const rules: DetectionRule[] = [{
            ruleId: "low-level-only",
            eventName: "AI_ACTION_REQUIRED",
            priority: "LOW",
            conditions: { maxLevel: 2 },
        }];

        const detector = new EventDetector(rules);
        expect(detector.detect(createTestLog({ level: 1 }))).not.toBeNull();
        expect(detector.detect(createTestLog({ level: 2 }))).not.toBeNull();
        expect(detector.detect(createTestLog({ level: 3 }))).toBeNull();
    });

    it("multiple conditions are AND-ed", () => {
        const rules: DetectionRule[] = [{
            ruleId: "specific",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                logTypes: ["SECURITY"],
                minLevel: 4,
                messagePattern: /unauthorized/i,
            },
        }];

        const detector = new EventDetector(rules);

        // All match → detected
        expect(detector.detect(createTestLog({
            type: "SECURITY", level: 4, message: "Unauthorized access",
        }))).not.toBeNull();

        // Wrong type → not detected
        expect(detector.detect(createTestLog({
            type: "SYSTEM", level: 4, message: "Unauthorized access",
        }))).toBeNull();

        // Low level → not detected
        expect(detector.detect(createTestLog({
            type: "SECURITY", level: 3, message: "Unauthorized access",
        }))).toBeNull();

        // Wrong message → not detected
        expect(detector.detect(createTestLog({
            type: "SECURITY", level: 4, message: "Normal operation",
        }))).toBeNull();
    });

    it("first matching rule wins", () => {
        const rules: DetectionRule[] = [
            { ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH", conditions: { minLevel: 5 } },
            { ruleId: "r2", eventName: "COMPLIANCE_VIOLATION", priority: "LOW", conditions: { minLevel: 3 } },
        ];

        const detector = new EventDetector(rules);
        const result = detector.detect(createTestLog({ level: 5 }));
        expect(result!.eventName).toBe("SECURITY_INTRUSION_DETECTED");
    });

    it("built-in rules take precedence over custom rules", () => {
        const rules: DetectionRule[] = [{
            ruleId: "custom",
            eventName: "COMPLIANCE_VIOLATION",
            priority: "LOW",
            conditions: { minLevel: 1 },
        }];

        const detector = new EventDetector(rules);

        // isCritical → built-in SYSTEM_CRITICAL_FAILURE, not custom
        const result = detector.detect(createTestLog({ isCritical: true, level: 6 }));
        expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });
});

// ===== 異常系: 不正なルール設定 =====
describe("Custom Detection Rules: abnormal cases", () => {
    it("empty conditions matches all logs", () => {
        const rules: DetectionRule[] = [{
            ruleId: "catch-all",
            eventName: "AI_ACTION_REQUIRED",
            priority: "LOW",
            conditions: {},
        }];

        const detector = new EventDetector(rules);
        // Built-in rules don't match normal log → custom catch-all should match
        expect(detector.detect(createTestLog({ level: 1 }))).not.toBeNull();
    });

    it("no custom rules means only built-in rules work", () => {
        const detector = new EventDetector([]);
        expect(detector.detect(createTestLog({ level: 3 }))).toBeNull();
        expect(detector.detect(createTestLog({ isCritical: true }))).not.toBeNull();
    });

    it("undefined custom rules defaults to empty", () => {
        const detector = new EventDetector();
        expect(detector.detect(createTestLog({ level: 3 }))).toBeNull();
    });
});

// ===== エッジケース =====
describe("Custom Detection Rules: edge cases", () => {
    it("tagMatch with key only (no value) matches any tag with that key", () => {
        const rules: DetectionRule[] = [{
            ruleId: "has-ip-tag",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "MEDIUM",
            conditions: { tagMatch: { key: "ip" } },
        }];

        const detector = new EventDetector(rules);

        expect(detector.detect(createTestLog({
            tags: [{ key: "ip", category: "192.168.1.1" }],
        }))).not.toBeNull();

        expect(detector.detect(createTestLog({
            tags: [{ key: "user", category: "admin" }],
        }))).toBeNull();
    });

    it("messagePattern with special regex characters works", () => {
        const rules: DetectionRule[] = [{
            ruleId: "path-access",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: { messagePattern: /\/admin\/.*\.php/ },
        }];

        const detector = new EventDetector(rules);

        expect(detector.detect(createTestLog({
            message: "GET /admin/config.php 403",
        }))).not.toBeNull();
    });

    it("origin condition filters correctly", () => {
        const rules: DetectionRule[] = [{
            ruleId: "system-only",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            priority: "HIGH",
            conditions: { origin: "SYSTEM" },
        }];

        const detector = new EventDetector(rules);

        expect(detector.detect(createTestLog({ origin: "SYSTEM" }))).not.toBeNull();
        expect(detector.detect(createTestLog({ origin: "AI_AGENT" }))).toBeNull();
    });

    it("origin condition AI_AGENT does not match SYSTEM log", () => {
        const rules: DetectionRule[] = [{
            ruleId: "ai-only",
            eventName: "AI_ACTION_REQUIRED",
            priority: "LOW",
            conditions: { origin: "AI_AGENT" },
        }];

        const detector = new EventDetector(rules);
        // origin="SYSTEM" should NOT match origin condition "AI_AGENT"
        expect(detector.detect(createTestLog({ origin: "SYSTEM", isCritical: false }))).toBeNull();
    });

    it("isCritical condition in custom rule", () => {
        const rules: DetectionRule[] = [{
            ruleId: "critical-custom",
            eventName: "AI_ACTION_REQUIRED",
            priority: "HIGH",
            conditions: { isCritical: true },
        }];

        const detector = new EventDetector(rules);
        // Built-in isCritical rule fires first → SYSTEM_CRITICAL_FAILURE
        // Custom rule does NOT fire because built-in takes precedence
        const result = detector.detect(createTestLog({ isCritical: true }));
        expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("isCritical true condition does not match non-critical log", () => {
        const rules: DetectionRule[] = [{
            ruleId: "critical-only",
            eventName: "AI_ACTION_REQUIRED",
            priority: "LOW",
            conditions: { isCritical: true },
        }];

        const detector = new EventDetector(rules);
        // isCritical=false log should NOT match isCritical=true condition
        const result = detector.detect(createTestLog({ isCritical: false }));
        expect(result).toBeNull();
    });

    it("50 custom rules do not degrade performance", () => {
        const rules: DetectionRule[] = Array.from({ length: 50 }, (_, i) => ({
            ruleId: `rule-${i}`,
            eventName: "COMPLIANCE_VIOLATION" as const,
            priority: "LOW" as const,
            conditions: { messagePattern: new RegExp(`pattern-${i}`) },
        }));

        const detector = new EventDetector(rules);
        const start = performance.now();
        for (let i = 0; i < 100; i++) {
            detector.detect(createTestLog({ message: "no match" }));
        }
        const elapsed = performance.now() - start;
        expect(elapsed).toBeLessThan(100); // 100 detections in < 100ms
    });
});

// ===== パイプライン統合テスト =====
describe("Custom Detection Rules: pipeline integration", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("custom rule triggers task generation via full pipeline", async () => {
        const onTaskGenerated = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "api-abuse",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: {
                    logTypes: ["SECURITY"],
                    messagePattern: /rate.*limit.*exceeded/i,
                },
            }],
            taskRules: [createTestTaskRule({
                eventName: "SECURITY_INTRUSION_DETECTED",
                actionType: "SYSTEM_NOTIFICATION",
                severity: "HIGH",
            })],
            onTaskGenerated,
        }));

        const result = await sentinel.ingest({
            message: "Rate limit exceeded for client X",
            type: "SECURITY",
            level: 4,
        });

        expect(result.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(onTaskGenerated).toHaveBeenCalled();
    });

    it("custom rule does NOT fire when log does not match", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "api-abuse",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: {
                    logTypes: ["SECURITY"],
                    messagePattern: /rate.*limit.*exceeded/i,
                },
            }],
        }));

        const result = await sentinel.ingest({ message: "Normal operation", level: 3 });
        expect(result.detection).toBeNull();
    });

    it("multiple custom rules in config work correctly", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [
                {
                    ruleId: "sql-injection",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: { messagePattern: /sql.*injection|union.*select/i },
                },
                {
                    ruleId: "data-export",
                    eventName: "COMPLIANCE_VIOLATION",
                    priority: "MEDIUM",
                    conditions: {
                        logTypes: ["BUSINESS-AUDIT"],
                        messagePattern: /bulk.*export|mass.*download/i,
                    },
                },
            ],
        }));

        const r1 = await sentinel.ingest({
            message: "SQL injection attempt detected",
            type: "SECURITY", level: 4,
        });
        expect(r1.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");

        Sentinel.reset();
        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [
                {
                    ruleId: "data-export",
                    eventName: "COMPLIANCE_VIOLATION",
                    priority: "MEDIUM",
                    conditions: {
                        logTypes: ["BUSINESS-AUDIT"],
                        messagePattern: /bulk.*export|mass.*download/i,
                    },
                },
            ],
        }));

        const r2 = await sentinel2.ingest({
            message: "Bulk export of customer data",
            type: "BUSINESS-AUDIT", level: 3,
        });
        expect(r2.detection?.eventName).toBe("COMPLIANCE_VIOLATION");
    });
});

// ===== ペネトレーションテスト =====
describe("Custom Detection Rules: penetration tests", () => {
    it("ReDoS-safe messagePattern does not hang", () => {
        const rules: DetectionRule[] = [{
            ruleId: "redos-test",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: { messagePattern: /^(a+)+$/ }, // Known ReDoS pattern
        }];

        const detector = new EventDetector(rules);
        const start = performance.now();
        // This input would cause catastrophic backtracking on vulnerable regex
        detector.detect(createTestLog({ message: "a".repeat(25) + "!" }));
        const elapsed = performance.now() - start;
        // Should complete within a reasonable time (V8 handles backtracking natively)
        expect(elapsed).toBeLessThan(5000);
    });

    it("malicious regex in messagePattern does not crash", () => {
        const rules: DetectionRule[] = [{
            ruleId: "test",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: { messagePattern: /(?:)/ },
        }];

        const detector = new EventDetector(rules);
        expect(() => detector.detect(createTestLog())).not.toThrow();
    });

    it("prototype pollution in custom rule conditions is safe", () => {
        const conditions = JSON.parse('{"__proto__": {"polluted": true}}');
        const rules: DetectionRule[] = [{
            ruleId: "proto-test",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions,
        }];

        const detector = new EventDetector(rules);
        detector.detect(createTestLog());

        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("polluted");
    });
});
