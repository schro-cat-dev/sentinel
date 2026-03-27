import { SentinelConfig, createDefaultConfig } from "./configs/sentinel-config";
import { IngestionEngine } from "./core/engine/ingestion-engine";
import { LogNormalizer } from "./core/engine/log-normalizer";
import { MaskingService } from "./security/masking-service";
import { IntegritySigner } from "./security/integrity-signer";
import { EventDetector } from "./core/detection/event-detector";
import { TaskGenerator } from "./core/task/task-generator";
import { TaskExecutor, TaskDispatchHandler } from "./core/task/task-executor";
import { Log } from "./types/log";
import { IngestionResult } from "./core/engine/types";

/**
 * Sentinel v1 Client SDK
 *
 * ログ → イベント検知 → タスク自動生成 → アクションディスパッチ
 * バックエンドサーバはGoに移行予定。本SDKはクライアント側の責務のみ担当。
 */
export class Sentinel {
    private static instance: Sentinel | null = null;
    private readonly engine: IngestionEngine;
    private readonly taskExecutor: TaskExecutor;
    private readonly config: SentinelConfig;
    private initialized = false;

    private constructor(config: SentinelConfig) {
        this.config = config;

        const normalizer = new LogNormalizer(config.serviceId);
        const masking = new MaskingService();
        const signer = new IntegritySigner();
        const detector = new EventDetector();
        const taskGenerator = new TaskGenerator(config.taskRules);
        this.taskExecutor = new TaskExecutor();

        this.engine = new IngestionEngine({
            config,
            normalizer,
            masking,
            signer,
            detector,
            taskGenerator,
            taskExecutor: this.taskExecutor,
        });

        this.initialized = true;
    }

    /**
     * Sentinel を初期化（シングルトン）
     */
    public static initialize(config: SentinelConfig): Sentinel {
        if (Sentinel.instance?.initialized) return Sentinel.instance;
        Sentinel.instance = new Sentinel(config);
        return Sentinel.instance;
    }

    /**
     * インスタンス取得
     */
    public static getInstance(): Sentinel {
        if (!Sentinel.instance) {
            throw new Error("Sentinel must be initialized first. Call Sentinel.initialize(config).");
        }
        return Sentinel.instance;
    }

    /**
     * インスタンスリセット（テスト用）
     */
    public static reset(): void {
        Sentinel.instance = null;
    }

    /**
     * ログ投入
     */
    public async ingest(log: Partial<Log>): Promise<IngestionResult> {
        return this.engine.handle(log);
    }

    /**
     * タスクアクションハンドラの登録
     */
    public onTaskAction(actionType: string, handler: TaskDispatchHandler): void {
        this.taskExecutor.registerHandler(actionType, handler);
    }

    /**
     * 現在の設定を取得
     */
    public getConfig(): Readonly<SentinelConfig> {
        return this.config;
    }
}

// Public API exports
export { createDefaultConfig } from "./configs/sentinel-config";
export type { SentinelConfig } from "./configs/sentinel-config";
export type { MaskingRule } from "./configs/masking-rule";
export type { Log, LogType, LogLevel, LogTag } from "./types/log";
export type { IngestionResult } from "./core/engine/types";
export type {
    TaskRule,
    GeneratedTask,
    TaskResult,
    TaskActionType,
    TaskPriority,
    TaskSeverity,
    TaskExecutionLevel,
} from "./types/task";
export type { SystemEventName, DetectionResult } from "./types/event";
export type { TaskDispatchHandler } from "./core/task/task-executor";
