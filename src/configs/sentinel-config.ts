import { MaskingRule } from "./masking-rule";
import { Log } from "../types/log";
import { TaskRule, GeneratedTask, TaskResult } from "../types/task";

/**
 * SDKの内部ログ出力先。利用者が注入することでconsole.warn等を制御可能。
 * 未指定時はproduction環境で抑制、それ以外でconsole出力。
 */
export interface SentinelLogger {
    warn(message: string, context?: Record<string, unknown>): void;
    error(message: string, context?: Record<string, unknown>): void;
}

/**
 * Sentinel SDK unified configuration
 */
export interface SentinelConfig {
    /** プロジェクト名 */
    projectName: string;

    /** サービス識別子（分散トレーシング用） */
    serviceId: string;

    /** 実行環境 */
    environment: "production" | "staging" | "development" | "local" | "test";

    /** PII マスキング設定 */
    masking: {
        enabled: boolean;
        rules: MaskingRule[];
        preserveFields: string[];
    };

    /** セキュリティ設定 */
    security: {
        enableHashChain: boolean;
        signingKeyId?: string;
    };

    /** タスク生成ルール（CORE VALUE） */
    taskRules: TaskRule[];

    /** イベントハンドラ */
    onLogProcessed?: (log: Log) => void;
    onTaskGenerated?: (task: GeneratedTask) => void;
    onTaskDispatched?: (result: TaskResult) => void;

    /** エラーハンドラ（パイプライン内部のswallowされるエラーを通知） */
    onError?: (error: Error, context: string) => void;

    /** SDK内部ログ出力先（省略時は環境に応じたデフォルト） */
    logger?: SentinelLogger;
}

/**
 * デフォルト設定
 */
export const createDefaultConfig = (
    overrides: Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">,
): SentinelConfig => {
    const defaults = {
        environment: "development" as const,
        masking: { enabled: false, rules: [] as MaskingRule[], preserveFields: ["traceId", "spanId"] },
        security: { enableHashChain: true },
        taskRules: [] as TaskRule[],
    };

    return {
        ...defaults,
        ...overrides,
        // Deep-merge nested objects to prevent silent security feature override (NEW-09)
        masking: {
            ...defaults.masking,
            ...overrides.masking,
        },
        security: {
            ...defaults.security,
            ...overrides.security,
        },
    };
};
