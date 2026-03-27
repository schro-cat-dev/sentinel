import { Log, LogType, LogLevel } from "../../src/types/log";
import { SentinelConfig, createDefaultConfig } from "../../src/configs/sentinel-config";
import { TaskRule } from "../../src/types/task";

/**
 * テスト用ログファクトリ
 */
export const createTestLog = (overrides: Partial<Log> = {}): Log => ({
    traceId: "test-trace-001",
    type: "SYSTEM" as LogType,
    level: 3 as LogLevel,
    timestamp: "2026-01-01T00:00:00.000Z",
    logicalClock: 1000,
    boundary: "test-service:handler",
    serviceId: "test-service",
    isCritical: false,
    message: "Test log message",
    origin: "SYSTEM",
    triggerAgent: false,
    tags: [],
    ...overrides,
});

/**
 * テスト用セキュリティログ
 */
export const createSecurityLog = (overrides: Partial<Log> = {}): Log =>
    createTestLog({
        type: "SECURITY",
        level: 5,
        message: "Suspicious activity detected from IP 192.168.1.100",
        boundary: "auth-service:login",
        tags: [{ key: "ip", category: "192.168.1.100" }],
        ...overrides,
    });

/**
 * テスト用クリティカルログ
 */
export const createCriticalLog = (overrides: Partial<Log> = {}): Log =>
    createTestLog({
        isCritical: true,
        level: 6,
        message: "Database connection pool exhausted",
        boundary: "db-service:connection-pool",
        ...overrides,
    });

/**
 * テスト用コンプライアンスログ
 */
export const createComplianceLog = (overrides: Partial<Log> = {}): Log =>
    createTestLog({
        type: "COMPLIANCE",
        level: 4,
        message: "Data retention policy violation detected",
        boundary: "audit-service:retention",
        actorId: "user-123",
        resourceIds: ["doc-456"],
        ...overrides,
    });

/**
 * テスト用タスクルール
 */
export const createTestTaskRule = (overrides: Partial<TaskRule> = {}): TaskRule => ({
    ruleId: "rule-001",
    eventName: "SYSTEM_CRITICAL_FAILURE",
    severity: "CRITICAL",
    actionType: "SYSTEM_NOTIFICATION",
    executionLevel: "AUTO",
    priority: 1,
    description: "Notify on critical system failure",
    executionParams: {
        notificationChannel: "#incidents",
    },
    guardrails: {
        requireHumanApproval: false,
        timeoutMs: 30000,
        maxRetries: 3,
    },
    ...overrides,
});

/**
 * テスト用設定
 */
export const createTestConfig = (overrides: Partial<SentinelConfig> = {}): SentinelConfig =>
    createDefaultConfig({
        projectName: "test-project",
        serviceId: "test-service",
        environment: "test",
        ...overrides,
    });
