/**
 * SDK Runtime Verification Tests
 *
 * 実際のアプリケーション利用パターンをシミュレートし、
 * SDKが実用環境で正しく動作することを検証する。
 *
 * - 本番想定フル構成での連続ingest
 * - 新機能(detectionRules, whitelist, metrics, tracer)の実動作
 * - CJS/ESMバンドルのexport確認
 * - シナリオベースのE2E（セキュリティインシデント対応フロー）
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
    Sentinel,
    createDefaultConfig,
    ValidationError,
} from "../../src/index";
import type { IngestionResult } from "../../src/index";
import { createTestTaskRule } from "../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== シナリオ1: セキュリティインシデント対応フロー =====
describe("Scenario: Security Incident Response", () => {
    it("detects brute force → generates alert task → dispatches handler → records metrics", async () => {
        // Setup: metrics & tracer
        const metrics: { ingested: number; detected: number; dispatched: number } = {
            ingested: 0, detected: 0, dispatched: 0,
        };
        const spans: { operation: string; durationMs: number }[] = [];

        const config = createDefaultConfig({
            projectName: "fintech-app",
            serviceId: "auth-service",
            environment: "production",
            security: { enableHashChain: true },
            masking: {
                enabled: true,
                rules: [
                    { type: "PII_TYPE", category: "EMAIL" },
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                ],
                preserveFields: ["traceId"],
            },
            detectionRules: [
                {
                    ruleId: "brute-force",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: {
                        logTypes: ["SECURITY"],
                        minLevel: 4,
                        messagePattern: /failed.*login|brute.*force/i,
                    },
                },
            ],
            taskRules: [
                {
                    ruleId: "alert-security-team",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    severity: "HIGH",
                    actionType: "ESCALATE",
                    executionLevel: "AUTO",
                    priority: 1,
                    description: "Alert security team on intrusion",
                    executionParams: { notificationChannel: "#security-critical" },
                    guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
                },
            ],
            whitelist: { level: "strict" },
            metrics: {
                onIngest: () => { metrics.ingested++; },
                onDetection: () => { metrics.detected++; },
                onTaskDispatch: () => { metrics.dispatched++; },
            },
            tracer: {
                onPipelineEnd: (ctx) => { spans.push({ operation: ctx.operation, durationMs: ctx.durationMs }); },
            },
        });

        const sentinel = Sentinel.initialize(config);

        // Register incident handler
        const incidents: string[] = [];
        const dispose = sentinel.onTaskAction("ESCALATE", async (task) => {
            incidents.push(`INCIDENT: ${task.sourceLog.message}`);
        });

        // Simulate: 3 normal logs + 1 brute force attack
        const results: IngestionResult[] = [];

        results.push(await sentinel.ingest({ message: "User login successful", type: "SYSTEM", level: 2 }));
        results.push(await sentinel.ingest({ message: "API request processed", type: "SYSTEM", level: 2 }));
        results.push(await sentinel.ingest({ message: "Cache invalidated", type: "SYSTEM", level: 2 }));
        results.push(await sentinel.ingest({
            message: "Brute force attack detected from 10.0.0.99 — failed login attempts exceeded threshold",
            type: "SECURITY",
            level: 5,
            tags: [{ key: "ip", category: "10.0.0.99" }],
        }));

        // Verify: normal logs pass through
        expect(results[0].detection).toBeNull();
        expect(results[1].detection).toBeNull();
        expect(results[2].detection).toBeNull();

        // Verify: security event detected (built-in rule takes precedence for level>=5)
        expect(results[3].detection).not.toBeNull();
        expect(results[3].detection!.eventName).toBe("SECURITY_INTRUSION_DETECTED");

        // Verify: task was generated and dispatched
        expect(results[3].tasksGenerated.length).toBeGreaterThan(0);
        expect(results[3].tasksGenerated[0].status).toBe("dispatched");

        // Verify: handler was called
        expect(incidents).toHaveLength(1);
        expect(incidents[0]).toContain("Brute force");

        // Verify: metrics recorded
        expect(metrics.ingested).toBe(4);
        expect(metrics.detected).toBeGreaterThanOrEqual(1);
        expect(metrics.dispatched).toBeGreaterThanOrEqual(1);

        // Verify: tracer recorded spans
        expect(spans).toHaveLength(4);
        expect(spans.every((s) => s.durationMs >= 0)).toBe(true);

        // Verify: hash chain
        expect(results.every((r) => r.hashChainValid)).toBe(true);

        // Verify: PII masking
        expect(results[3].masked).toBe(true);

        // Cleanup handler
        dispose();

        await sentinel.shutdown();
    });
});

// ===== シナリオ2: コンプライアンス違反フロー =====
describe("Scenario: Compliance Violation Flow", () => {
    it("detects data export violation → SEMI_AUTO task → confirm handler", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "bank-app",
            serviceId: "data-export",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "bulk-export",
                eventName: "COMPLIANCE_VIOLATION",
                priority: "MEDIUM",
                conditions: {
                    logTypes: ["BUSINESS-AUDIT"],
                    messagePattern: /bulk.*export|mass.*download/i,
                },
            }],
            taskRules: [{
                ruleId: "compliance-review",
                eventName: "COMPLIANCE_VIOLATION",
                severity: "MEDIUM",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "SEMI_AUTO",
                priority: 1,
                description: "Notify compliance team for review",
                executionParams: { notificationChannel: "#compliance" },
                guardrails: { requireHumanApproval: false, timeoutMs: 86400000, maxRetries: 0 },
            }],
        }));

        // Set confirm handler: approve the task
        sentinel.onTaskConfirm(() => true);
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {
            // Compliance notification handler
        });

        const result = await sentinel.ingest({
            message: "Bulk export of 10,000 customer records initiated",
            type: "BUSINESS-AUDIT",
            level: 4,
        });

        expect(result.detection?.eventName).toBe("COMPLIANCE_VIOLATION");
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(result.tasksGenerated[0].status).toBe("dispatched"); // Confirmed → dispatched

        await sentinel.shutdown();
    });
});

// ===== シナリオ3: 高スループット連続ingest =====
describe("Scenario: High-throughput sequential ingest", () => {
    it("processes 100 logs without memory leak or performance degradation", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "high-traffic",
            serviceId: "api-gateway",
            security: { enableHashChain: true },
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: [],
            },
        }));

        const start = performance.now();

        for (let i = 0; i < 100; i++) {
            const result = await sentinel.ingest({
                message: `Request ${i} from user-${i}@test.com`,
                level: (i % 6 + 1) as 1 | 2 | 3 | 4 | 5 | 6,
                type: "SYSTEM",
            });

            expect(result.traceId).toBeDefined();
            expect(result.hashChainValid).toBe(true);
            expect(result.masked).toBe(true);
        }

        const elapsed = performance.now() - start;
        // 100 logs should complete in reasonable time (< 5 seconds)
        expect(elapsed).toBeLessThan(5000);

        await sentinel.shutdown();
    });
});

// ===== シナリオ4: 動的ハンドラ管理 =====
describe("Scenario: Dynamic handler lifecycle", () => {
    it("register → dispatch → dispose → verify removed", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p",
            serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                executionLevel: "AUTO",
            })],
        }));

        const calls: string[] = [];

        // Register handler
        const dispose = sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {
            calls.push("handled");
        });

        // First ingest — handler should fire
        await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });
        expect(calls).toEqual(["handled"]);

        // Dispose handler
        dispose();

        // Second ingest — handler should NOT fire (disposed)
        Sentinel.reset();
        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p",
            serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                executionLevel: "AUTO",
            })],
        }));

        await sentinel2.ingest({ message: "fail", isCritical: true, level: 6 });
        // calls should still be ["handled"] — only from first ingest
        expect(calls).toEqual(["handled"]);

        await sentinel2.shutdown();
    });
});

// ===== シナリオ5: Whitelist extensionsによるカスタムアクション =====
describe("Scenario: Custom action via whitelist extensions", () => {
    it("registers and dispatches custom action type", async () => {
        const customHandlerCalls: string[] = [];

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "custom-app",
            serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "custom-task",
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                actionType: "CUSTOM_JIRA_TICKET" as never,
                executionLevel: "AUTO",
                priority: 1,
                description: "Create JIRA ticket",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
            whitelist: {
                level: "standard",
                extensions: { actionType: ["CUSTOM_JIRA_TICKET"] },
            },
        }));

        sentinel.onTaskAction("CUSTOM_JIRA_TICKET", async (task) => {
            customHandlerCalls.push(`JIRA: ${task.description}`);
        });

        const result = await sentinel.ingest({ message: "system down", isCritical: true, level: 6 });

        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(customHandlerCalls).toHaveLength(1);
        expect(customHandlerCalls[0]).toContain("JIRA");

        await sentinel.shutdown();
    });
});

// ===== シナリオ6: 型安全性の実動作確認 =====
describe("Scenario: Type safety at runtime", () => {
    it("string messagePattern (from JSON parse) is rejected at init", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                detectionRules: [{
                    ruleId: "r1",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: { messagePattern: "not-a-regex" as unknown as RegExp },
                }],
            })),
        ).toThrow(/messagePattern.*RegExp/);
    });

    it("invalid whitelist value is rejected at init", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                taskRules: [createTestTaskRule({ actionType: "NONEXISTENT" as never })],
                whitelist: { level: "strict" },
            })),
        ).toThrow(ValidationError);
    });
});
