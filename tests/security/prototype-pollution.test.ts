/**
 * Security Test: Prototype Pollution
 *
 * Tests that malicious __proto__ / constructor properties in
 * user-provided config or log data do not pollute Object.prototype.
 *
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
 */
import { describe, it, expect, afterEach } from "vitest";
import { TaskGenerator } from "../../src/core/task/task-generator";
import { MaskingService } from "../../src/security/masking-service";
import { createTestTaskRule, createTestLog } from "../helpers/fixtures";
import type { DetectionResult, SystemEventName } from "../../src/types/event";

describe("Security: Prototype Pollution resistance", () => {
    afterEach(() => {
        // Verify global prototype is clean after each test
        const obj: Record<string, unknown> = {};
        expect(obj).not.toHaveProperty("isAdmin");
        expect(obj).not.toHaveProperty("polluted");
        expect(obj).not.toHaveProperty("injected");
        expect(Object.prototype).not.toHaveProperty("isAdmin");
        expect(Object.prototype).not.toHaveProperty("polluted");
    });

    describe("TaskGenerator", () => {
        it("does not propagate __proto__ from executionParams", () => {
            const maliciousRule = createTestTaskRule({
                executionParams: JSON.parse(
                    '{"__proto__": {"isAdmin": true}, "notificationChannel": "#test"}'
                ),
            });

            const generator = new TaskGenerator([maliciousRule]);

            const detection: DetectionResult<SystemEventName> = {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                payload: {
                    component: "test",
                    errorDetails: "test error",
                },
                priority: "HIGH",
            };

            const tasks = generator.generate(detection, createTestLog());
            expect(tasks.length).toBeGreaterThan(0);

            // Verify prototype was NOT polluted
            const clean: Record<string, unknown> = {};
            expect(clean).not.toHaveProperty("isAdmin");
        });

        it("does not propagate constructor.prototype from guardrails", () => {
            const maliciousRule = createTestTaskRule({
                guardrails: JSON.parse(
                    '{"constructor": {"prototype": {"polluted": true}}, "requireHumanApproval": false, "timeoutMs": 5000, "maxRetries": 1}'
                ),
            });

            const generator = new TaskGenerator([maliciousRule]);

            const detection: DetectionResult<SystemEventName> = {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                payload: {
                    component: "test",
                    errorDetails: "test",
                },
                priority: "HIGH",
            };

            const tasks = generator.generate(detection, createTestLog());
            expect(tasks.length).toBeGreaterThan(0);

            const clean: Record<string, unknown> = {};
            expect(clean).not.toHaveProperty("polluted");
        });
    });

    describe("MaskingService", () => {
        it("does not pollute prototype via __proto__ in log data", () => {
            const maliciousLog = JSON.parse(
                '{"message": "test", "__proto__": {"injected": true}}'
            );

            MaskingService.mask(maliciousLog, []);

            const clean: Record<string, unknown> = {};
            expect(clean).not.toHaveProperty("injected");
        });

        it("handles deeply nested __proto__ in log metadata", () => {
            const log = createTestLog({
                details: JSON.stringify({
                    nested: {
                        __proto__: { deep: true },
                    },
                }),
            });

            const masked = MaskingService.mask(log, []);
            expect(masked).toBeDefined();

            const clean: Record<string, unknown> = {};
            expect(clean).not.toHaveProperty("deep");
        });

        it("handles constructor property in tags", () => {
            const log = createTestLog({
                tags: [
                    { key: "constructor", category: "prototype" },
                    { key: "__proto__", category: "attack" },
                ],
            });

            const masked = MaskingService.mask(log, []) as Record<string, unknown>;
            expect(masked).toBeDefined();

            const clean: Record<string, unknown> = {};
            expect(clean).not.toHaveProperty("prototype");
        });
    });
});
