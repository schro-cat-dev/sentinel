import { describe, it, expect, beforeEach } from "vitest";
import { TaskGenerator } from "../../../src/core/task/task-generator";
import { TaskRule } from "../../../src/types/task";
import { DetectionResult, SystemEventName } from "../../../src/types/event";
import {
    createTestLog,
    createCriticalLog,
    createSecurityLog,
    createTestTaskRule,
} from "../../helpers/fixtures";

describe("TaskGenerator", () => {
    const defaultRules: TaskRule[] = [
        createTestTaskRule({
            ruleId: "crit-notify",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "CRITICAL",
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "AUTO",
            priority: 1,
            description: "Notify critical failure",
        }),
        createTestTaskRule({
            ruleId: "crit-kill",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH",
            actionType: "KILL_SWITCH",
            executionLevel: "SEMI_AUTO",
            priority: 2,
            description: "Kill switch for critical failure",
            guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 },
        }),
        createTestTaskRule({
            ruleId: "sec-analyze",
            eventName: "SECURITY_INTRUSION_DETECTED",
            severity: "HIGH",
            actionType: "AI_ANALYZE",
            executionLevel: "AUTO",
            priority: 1,
            description: "AI analysis of intrusion",
        }),
        createTestTaskRule({
            ruleId: "comp-escalate",
            eventName: "COMPLIANCE_VIOLATION",
            severity: "MEDIUM",
            actionType: "ESCALATE",
            executionLevel: "MANUAL",
            priority: 1,
            description: "Escalate compliance violation",
        }),
    ];

    let generator: TaskGenerator;

    beforeEach(() => {
        generator = new TaskGenerator(defaultRules);
    });

    describe("rule indexing", () => {
        it("counts total rules", () => {
            expect(generator.getRuleCount()).toBe(4);
        });

        it("retrieves rules by event name", () => {
            const rules = generator.getRulesForEvent("SYSTEM_CRITICAL_FAILURE");
            expect(rules).toHaveLength(2);
        });

        it("returns empty array for unregistered event", () => {
            const rules = generator.getRulesForEvent("NONEXISTENT_EVENT");
            expect(rules).toHaveLength(0);
        });
    });

    describe("task generation - SYSTEM_CRITICAL_FAILURE", () => {
        const detection: DetectionResult<SystemEventName> = {
            eventName: "SYSTEM_CRITICAL_FAILURE",
            priority: "HIGH",
            payload: { component: "db", errorDetails: "pool exhausted" },
        };

        it("generates tasks for matching event", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            expect(tasks.length).toBeGreaterThan(0);
        });

        it("includes correct sourceLog metadata", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            expect(tasks[0].sourceLog.traceId).toBe(log.traceId);
            expect(tasks[0].sourceLog.message).toBe(log.message);
            expect(tasks[0].sourceLog.boundary).toBe(log.boundary);
        });

        it("generates unique taskIds", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            const ids = tasks.map((t) => t.taskId);
            expect(new Set(ids).size).toBe(ids.length);
        });

        it("sorts tasks by priority (ascending)", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            for (let i = 1; i < tasks.length; i++) {
                expect(tasks[i].priority).toBeGreaterThanOrEqual(tasks[i - 1].priority);
            }
        });

        it("includes both CRITICAL and HIGH severity rules for CRITICAL log", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            const ruleIds = tasks.map((t) => t.ruleId);
            expect(ruleIds).toContain("crit-notify");
            expect(ruleIds).toContain("crit-kill");
        });

        it("assigns CRITICAL severity to all tasks from critical log", () => {
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            for (const task of tasks) {
                expect(task.severity).toBe("CRITICAL");
            }
        });
    });

    describe("task generation - SECURITY_INTRUSION_DETECTED", () => {
        const detection: DetectionResult<SystemEventName> = {
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            payload: { ip: "10.0.0.1", severity: 5, rawLog: createSecurityLog() },
        };

        it("generates AI_ANALYZE task", () => {
            const log = createSecurityLog();
            const tasks = generator.generate(detection, log);
            expect(tasks).toHaveLength(1);
            expect(tasks[0].ruleId).toBe("sec-analyze");
            expect(tasks[0].actionType).toBe("AI_ANALYZE");
        });
    });

    describe("task generation - COMPLIANCE_VIOLATION", () => {
        const detection: DetectionResult<SystemEventName> = {
            eventName: "COMPLIANCE_VIOLATION",
            priority: "HIGH",
            payload: { ruleId: "R1", documentId: "D1", userId: "U1" },
        };

        it("generates ESCALATE task for compliance violation", () => {
            const log = createTestLog({ type: "COMPLIANCE", level: 4, message: "violation" });
            const tasks = generator.generate(detection, log);
            expect(tasks).toHaveLength(1);
            expect(tasks[0].actionType).toBe("ESCALATE");
            expect(tasks[0].executionLevel).toBe("MANUAL");
        });
    });

    describe("severity threshold filtering", () => {
        it("filters out rules with higher severity threshold than actual", () => {
            // A rule requiring CRITICAL severity should not fire for a MEDIUM event
            const highOnlyRules: TaskRule[] = [
                createTestTaskRule({
                    ruleId: "high-only",
                    eventName: "SYSTEM_CRITICAL_FAILURE",
                    severity: "CRITICAL",
                    actionType: "KILL_SWITCH",
                }),
            ];
            const gen = new TaskGenerator(highOnlyRules);
            // SLA level 4 = MEDIUM priority, detection MEDIUM
            const detection: DetectionResult<SystemEventName> = {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                priority: "MEDIUM",
                payload: { component: "sla", errorDetails: "slow" },
            };
            const log = createTestLog({ type: "SLA", level: 4 });
            const tasks = gen.generate(detection, log);
            // HIGH severity log should match CRITICAL rule? No - HIGH < CRITICAL
            // SLA level 4 with MEDIUM priority = HIGH severity
            // CRITICAL rule requires CRITICAL, but actual is HIGH -> filtered out
            expect(tasks).toHaveLength(0);
        });
    });

    describe("no matching rules", () => {
        it("returns empty array for unregistered event", () => {
            const detection: DetectionResult<SystemEventName> = {
                eventName: "AI_ACTION_REQUIRED",
                priority: "LOW",
                payload: { reason: "test", suggestedTask: "analyze", context: null },
            };
            const log = createTestLog();
            const tasks = generator.generate(detection, log);
            expect(tasks).toHaveLength(0);
        });
    });

    describe("empty rules", () => {
        it("generates no tasks when initialized with empty rules", () => {
            const emptyGen = new TaskGenerator([]);
            expect(emptyGen.getRuleCount()).toBe(0);
            const detection: DetectionResult<SystemEventName> = {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                priority: "HIGH",
                payload: { component: "x", errorDetails: "y" },
            };
            const tasks = emptyGen.generate(detection, createCriticalLog());
            expect(tasks).toHaveLength(0);
        });
    });

    describe("task structure completeness", () => {
        it("includes all required fields in generated task", () => {
            const detection: DetectionResult<SystemEventName> = {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                priority: "HIGH",
                payload: { component: "db", errorDetails: "down" },
            };
            const log = createCriticalLog();
            const tasks = generator.generate(detection, log);
            const task = tasks[0];

            expect(task.taskId).toBeDefined();
            expect(task.ruleId).toBeDefined();
            expect(task.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
            expect(task.severity).toBeDefined();
            expect(task.actionType).toBeDefined();
            expect(task.executionLevel).toBeDefined();
            expect(task.priority).toBeDefined();
            expect(task.description).toBeDefined();
            expect(task.executionParams).toBeDefined();
            expect(task.guardrails).toBeDefined();
            expect(task.sourceLog).toBeDefined();
            expect(task.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });
    });
});
