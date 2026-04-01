/**
 * Whitelist Routing E2E Tests
 *
 * ホワイトリストが各パイプラインステージまで正しく到達し、
 * 設定が反映されているかを全経路で検証する。
 *
 * 検証ポイント:
 * 1階層目（適用箇所へのルーティング）:
 *   - EventDetector: eventName, detectionPriority
 *   - TaskGenerator: eventName→ruleIndex, severity→threshold
 *   - TaskExecutor: actionType→handler, executionLevel→dispatchStatus
 *   - MaskingService: piiCategory→pattern
 *
 * 2階層目（各適用先内部での反映）:
 *   - 正しい値 → 正常動作
 *   - 不正な値 → 初期化時にブロック（standard/strict）
 *   - 設定変更 → 再初期化で反映
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { createTestTaskRule, createTestLog } from "../../helpers/fixtures";
import { EventDetector } from "../../../src/core/detection/event-detector";
import type { DetectionRule } from "../../../src/types/event";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== Route 1: EventDetector (eventName, detectionPriority) =====
describe("Routing E2E: EventDetector", () => {
    it("valid detectionRule eventName reaches EventDetector and triggers detection", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "r1",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: { messagePattern: /test-intrusion/ },
            }],
        }));

        const result = await sentinel.ingest({
            message: "test-intrusion detected",
            type: "SYSTEM", level: 3,
        });
        expect(result.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");
    });

    it("invalid detectionRule eventName is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1",
                    eventName: "TYPO_EVENT" as never,
                    priority: "HIGH",
                    conditions: {},
                }],
            })),
        ).toThrow(ValidationError);
    });

    it("invalid detectionRule priority is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "ULTRA" as never,
                    conditions: {},
                }],
            })),
        ).toThrow(ValidationError);
    });

    it("valid priority propagates to DetectionResult", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "r1",
                eventName: "COMPLIANCE_VIOLATION",
                priority: "MEDIUM",
                conditions: { messagePattern: /test/ },
            }],
        }));

        const result = await sentinel.ingest({ message: "test", level: 2 });
        expect(result.detection?.priority).toBe("MEDIUM");
    });
});

// ===== Route 2: TaskGenerator (eventName→ruleIndex, severity→threshold) =====
describe("Routing E2E: TaskGenerator", () => {
    it("valid taskRule eventName routes to correct task generation", async () => {
        const onTaskGenerated = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "d1",
                eventName: "COMPLIANCE_VIOLATION",
                priority: "HIGH",
                conditions: { messagePattern: /violation/ },
            }],
            taskRules: [createTestTaskRule({
                eventName: "COMPLIANCE_VIOLATION",
                severity: "HIGH",
            })],
            onTaskGenerated,
        }));

        await sentinel.ingest({ message: "compliance violation", level: 4 });
        expect(onTaskGenerated).toHaveBeenCalled();
    });

    it("invalid taskRule eventName is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ eventName: "MISSPELLED" as never })],
            })),
        ).toThrow(ValidationError);
    });

    it("invalid severity is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ severity: "MEGA" as never })],
            })),
        ).toThrow(ValidationError);
    });

    it("severity threshold filtering works with valid values", async () => {
        const onTaskGenerated = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",  // Only fires when actual severity >= CRITICAL
            })],
            onTaskGenerated,
        }));

        // isCritical → SYSTEM_CRITICAL_FAILURE → severity=CRITICAL → matches rule
        await sentinel.ingest({ message: "critical failure", isCritical: true, level: 6 });
        expect(onTaskGenerated).toHaveBeenCalled();
    });
});

// ===== Route 3: TaskExecutor (actionType→handler, executionLevel) =====
describe("Routing E2E: TaskExecutor", () => {
    it("valid actionType dispatches to registered handler", async () => {
        const handler = vi.fn().mockResolvedValue({ status: "completed" });
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
                severity: "CRITICAL",
            })],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });
        expect(handler).toHaveBeenCalled();
    });

    it("invalid actionType in onTaskAction is rejected at runtime", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));
        expect(() =>
            sentinel.onTaskAction("FAKE_ACTION", async () => ({ status: "completed" })),
        ).toThrow(ValidationError);
    });

    it("invalid actionType in taskRule is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ actionType: "FAKE" as never })],
            })),
        ).toThrow(ValidationError);
    });

    it("invalid executionLevel in taskRule is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ executionLevel: "TURBO" as never })],
            })),
        ).toThrow(ValidationError);
    });

    it("executionLevel AUTO dispatches immediately", async () => {
        const handler = vi.fn().mockResolvedValue({ status: "completed" });
        const onDispatched = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                executionLevel: "AUTO",
                severity: "CRITICAL",
            })],
            onTaskDispatched: onDispatched,
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

        await sentinel.ingest({ message: "crit", isCritical: true, level: 6 });
        expect(handler).toHaveBeenCalled();
        expect(onDispatched).toHaveBeenCalled();
    });
});

// ===== Route 4: MaskingService (piiCategory→pattern) =====
describe("Routing E2E: MaskingService", () => {
    it("valid PII category is applied during masking", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: [],
            },
        }));

        const result = await sentinel.ingest({
            message: "Contact alice@secret.com for details",
            level: 2,
        });
        expect(result.masked).toBe(true);
    });

    it("invalid PII category is blocked at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "SSN" as never }],
                    preserveFields: [],
                },
            })),
        ).toThrow(ValidationError);
    });

    it("extended PII categories (JAPAN_ACCOUNT etc.) are accepted", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                masking: {
                    enabled: true,
                    rules: [
                        { type: "PII_TYPE", category: "JAPAN_ACCOUNT" },
                        { type: "PII_TYPE", category: "HEALTH_INSURANCE" },
                    ],
                    preserveFields: [],
                },
            })),
        ).not.toThrow();
    });
});

// ===== 設定変更後の再初期化テスト =====
describe("Routing E2E: config change and re-initialization", () => {
    it("changing from standard to off allows invalid values after re-init", () => {
        // First: standard → rejects
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
                whitelist: { level: "standard" },
            })),
        ).toThrow(ValidationError);

        Sentinel.reset();

        // Second: off → accepts
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
                whitelist: { level: "off" },
            })),
        ).not.toThrow();
    });

    it("changing from off to strict tightens validation after re-init", () => {
        // First: off → accepts
        Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
            whitelist: { level: "off" },
        }));

        Sentinel.reset();

        // Second: strict → rejects
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
                whitelist: { level: "strict" },
            })),
        ).toThrow(ValidationError);
    });

    it("adding extension after re-init allows previously rejected value", () => {
        // First: no extension → rejects CUSTOM
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ eventName: "CUSTOM" as never })],
            })),
        ).toThrow(ValidationError);

        Sentinel.reset();

        // Second: with extension → accepts CUSTOM
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule({ eventName: "CUSTOM" as never })],
                whitelist: { extensions: { eventName: ["CUSTOM"] } },
            })),
        ).not.toThrow();
    });
});

// ===== 全パイプライン統合: 検知→タスク生成→ディスパッチ =====
describe("Routing E2E: full pipeline with whitelist", () => {
    it("valid config flows through entire pipeline", async () => {
        const handler = vi.fn().mockResolvedValue({ status: "completed" });
        const onTaskGenerated = vi.fn();
        const onDispatched = vi.fn();

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "prod", serviceId: "api",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "brute-force",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: {
                    logTypes: ["SECURITY"],
                    messagePattern: /brute.*force/i,
                },
            }],
            taskRules: [createTestTaskRule({
                eventName: "SECURITY_INTRUSION_DETECTED",
                actionType: "ESCALATE",
                severity: "HIGH",
                executionLevel: "AUTO",
            })],
            onTaskGenerated,
            onTaskDispatched: onDispatched,
        }));
        sentinel.onTaskAction("ESCALATE", handler);

        const result = await sentinel.ingest({
            message: "Brute force attack detected",
            type: "SECURITY", level: 4,
        });

        // Detection reached EventDetector
        expect(result.detection?.eventName).toBe("SECURITY_INTRUSION_DETECTED");
        // Task generated by TaskGenerator
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(onTaskGenerated).toHaveBeenCalled();
        // Handler dispatched by TaskExecutor
        expect(handler).toHaveBeenCalled();
        expect(onDispatched).toHaveBeenCalled();
    });
});
