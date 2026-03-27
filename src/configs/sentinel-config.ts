import { MaskingRule } from "./masking-rule";
import { Log } from "../types/log";
import { TaskRule, GeneratedTask, TaskResult } from "../types/task";

/**
 * Sentinel v1 SDK unified configuration
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
}

/**
 * デフォルト設定
 */
export const createDefaultConfig = (
    overrides: Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">,
): SentinelConfig => ({
    environment: "development",
    masking: { enabled: false, rules: [], preserveFields: ["traceId", "spanId"] },
    security: { enableHashChain: true },
    taskRules: [],
    ...overrides,
});
