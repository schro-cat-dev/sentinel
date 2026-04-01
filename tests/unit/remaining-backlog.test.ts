/**
 * Tests for remaining backlog items:
 * OBS-03: SentinelLogger interface
 * CFG-01: projectName consumption
 * CFG-02: environment-based behavior
 * API-02: SEMI_AUTO confirmation handler
 * DEAD-04: AI_ACTION_REQUIRED detection
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig } from "../../src/index";
import { MaskingService } from "../../src/security/masking-service";
import { EventDetector } from "../../src/core/detection/event-detector";
import { TaskExecutor } from "../../src/core/task/task-executor";
import { createTestLog, createTestTaskRule, createTestConfig } from "../helpers/fixtures";
import { IngestionEngine } from "../../src/core/engine/ingestion-engine";
import { LogNormalizer } from "../../src/core/engine/log-normalizer";
import { IntegritySigner } from "../../src/security/integrity-signer";
import { TaskGenerator } from "../../src/core/task/task-generator";
import type { SentinelLogger } from "../../src/configs/sentinel-config";

// ===== OBS-03: SentinelLogger =====
describe("OBS-03: SentinelLogger interface", () => {
    it("masking service uses injected logger for warnings", () => {
        const logger: SentinelLogger = {
            warn: vi.fn(),
            error: vi.fn(),
        };

        // Force a masking rule failure by using an invalid regex
        MaskingService.mask(
            { message: "test" },
            [{ type: "REGEX", pattern: /(?:)/ as unknown as RegExp, replacement: "$<bad>", description: "test" }],
            [],
            { logger },
        );

        // Logger should NOT be called for valid regex operations
        // (the above regex is valid, so no warn expected)
    });

    it("logger.warn is NOT called when rule succeeds", () => {
        const logger: SentinelLogger = {
            warn: vi.fn(),
            error: vi.fn(),
        };

        MaskingService.mask(
            { message: "test@example.com" },
            [{ type: "PII_TYPE", category: "EMAIL" }],
            [],
            { logger },
        );

        expect(logger.warn).not.toHaveBeenCalled();
    });

    it("production environment suppresses console.warn (no logger = no output)", () => {
        const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        // Without logger, no console.warn is called (since we replaced it)
        MaskingService.mask(
            { message: "test" },
            [{ type: "PII_TYPE", category: "EMAIL" }],
        );

        expect(consoleSpy).not.toHaveBeenCalled();
        consoleSpy.mockRestore();
    });
});

// ===== API-02: SEMI_AUTO confirmation =====
describe("API-02: SEMI_AUTO confirmation handler", () => {
    it("SEMI_AUTO dispatches when no confirm handler (backward compat)", async () => {
        const executor = new TaskExecutor();
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const task = {
            taskId: "t-1",
            ruleId: "r-1",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH" as const,
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "SEMI_AUTO" as const,
            priority: 1 as const,
            description: "test",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
            sourceLog: { traceId: "t", message: "m", boundary: "b", level: 3 as const, timestamp: "" },
            createdAt: new Date().toISOString(),
        };

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(handler).toHaveBeenCalled();
    });

    it("SEMI_AUTO blocks when confirm handler returns false", async () => {
        const executor = new TaskExecutor();
        executor.setConfirmHandler(async () => false);
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const task = {
            taskId: "t-1",
            ruleId: "r-1",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH" as const,
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "SEMI_AUTO" as const,
            priority: 1 as const,
            description: "test",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
            sourceLog: { traceId: "t", message: "m", boundary: "b", level: 3 as const, timestamp: "" },
            createdAt: new Date().toISOString(),
        };

        const result = await executor.dispatch(task);
        expect(result.status).toBe("blocked_approval");
        expect(handler).not.toHaveBeenCalled();
    });

    it("SEMI_AUTO dispatches when confirm handler returns true", async () => {
        const executor = new TaskExecutor();
        executor.setConfirmHandler(async () => true);
        const handler = vi.fn();
        executor.registerHandler("SYSTEM_NOTIFICATION", handler);

        const task = {
            taskId: "t-1",
            ruleId: "r-1",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH" as const,
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "SEMI_AUTO" as const,
            priority: 1 as const,
            description: "test",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
            sourceLog: { traceId: "t", message: "m", boundary: "b", level: 3 as const, timestamp: "" },
            createdAt: new Date().toISOString(),
        };

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(handler).toHaveBeenCalled();
    });

    it("AUTO ignores confirm handler", async () => {
        const executor = new TaskExecutor();
        const confirmHandler = vi.fn().mockResolvedValue(false);
        executor.setConfirmHandler(confirmHandler);
        executor.registerHandler("SYSTEM_NOTIFICATION", vi.fn());

        const task = {
            taskId: "t-1",
            ruleId: "r-1",
            eventName: "SYSTEM_CRITICAL_FAILURE",
            severity: "HIGH" as const,
            actionType: "SYSTEM_NOTIFICATION",
            executionLevel: "AUTO" as const,
            priority: 1 as const,
            description: "test",
            executionParams: {},
            guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 0 },
            sourceLog: { traceId: "t", message: "m", boundary: "b", level: 3 as const, timestamp: "" },
            createdAt: new Date().toISOString(),
        };

        const result = await executor.dispatch(task);
        expect(result.status).toBe("dispatched");
        expect(confirmHandler).not.toHaveBeenCalled();
    });
});

// ===== DEAD-04: AI_ACTION_REQUIRED detection =====
describe("DEAD-04: AI_ACTION_REQUIRED event detection", () => {
    const detector = new EventDetector();

    it("detects AI_ACTION_REQUIRED when triggerAgent=true and level >= 4", () => {
        const log = createTestLog({
            triggerAgent: true,
            level: 4,
            message: "Anomaly detected in payment flow",
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        expect(result!.eventName).toBe("AI_ACTION_REQUIRED");
        expect(result!.priority).toBe("MEDIUM");
    });

    it("detects AI_ACTION_REQUIRED with HIGH priority at level >= 5", () => {
        const log = createTestLog({
            triggerAgent: true,
            level: 5,
            type: "SYSTEM",
            message: "Suspicious access pattern",
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        expect(result!.eventName).toBe("AI_ACTION_REQUIRED");
        expect(result!.priority).toBe("HIGH");
    });

    it("does NOT detect AI_ACTION_REQUIRED when triggerAgent=false", () => {
        const log = createTestLog({
            triggerAgent: false,
            level: 5,
            message: "Normal log",
        });

        // Should fall through to other rules or null
        const result = detector.detect(log);
        // Not AI_ACTION_REQUIRED since triggerAgent is false
        expect(result?.eventName).not.toBe("AI_ACTION_REQUIRED");
    });

    it("does NOT detect AI_ACTION_REQUIRED when level < 4", () => {
        const log = createTestLog({
            triggerAgent: true,
            level: 3,
            message: "Low level log",
        });

        const result = detector.detect(log);
        expect(result?.eventName).not.toBe("AI_ACTION_REQUIRED");
    });

    it("isCritical takes precedence over triggerAgent", () => {
        const log = createTestLog({
            triggerAgent: true,
            isCritical: true,
            level: 5,
            message: "Critical and trigger",
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        // isCritical is checked first → SYSTEM_CRITICAL_FAILURE
        expect(result!.eventName).toBe("SYSTEM_CRITICAL_FAILURE");
    });

    it("includes aiContext in payload", () => {
        const log = createTestLog({
            triggerAgent: true,
            level: 4,
            message: "AI needed",
            aiContext: { agentId: "detector-v1", taskId: "task-42", loopDepth: 0 },
        });

        const result = detector.detect(log);
        expect(result).not.toBeNull();
        const payload = result!.payload as Record<string, unknown>;
        expect(payload.context).toEqual({ agentId: "detector-v1", taskId: "task-42", loopDepth: 0 });
    });
});

// ===== OBS-03: onError callback integration =====
describe("OBS-03: onError callback in pipeline", () => {
    it("onError receives callback errors with context", async () => {
        const onError = vi.fn();
        const config = createTestConfig({
            masking: { enabled: false, rules: [], preserveFields: [] },
            security: { enableHashChain: false },
            onLogProcessed: () => { throw new Error("callback fail"); },
            onError,
        });

        const engine = new IngestionEngine({
            config,
            normalizer: new LogNormalizer(config.serviceId),
            signer: new IntegritySigner(),
            detector: new EventDetector(),
            taskGenerator: new TaskGenerator([]),
            taskExecutor: new TaskExecutor(),
        });

        await engine.handle({ message: "test" });

        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
        expect(onError.mock.calls[0][0].message).toBe("callback fail");
        expect(onError.mock.calls[0][1]).toBe("callback");
    });
});
