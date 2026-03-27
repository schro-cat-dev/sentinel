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
import { TransportConfig, RemoteTransport } from "./transport/transport";
import { validateLogInput, ValidationError } from "./validation/log-validator";

/**
 * SentinelOptions はSentinel初期化時のオプション
 */
export interface SentinelOptions {
    /**
     * Transport設定（省略時はローカルパイプラインのみ）
     */
    transport?: TransportConfig;
}

/**
 * Sentinel v2 Client SDK
 *
 * ログ → イベント検知 → タスク自動生成 → アクションディスパッチ
 * Transport設定でローカル処理 / Goサーバへのリモート送信 / 両方を選択可能。
 */
export class Sentinel {
    private static instance: Sentinel | null = null;
    private readonly engine: IngestionEngine;
    private readonly taskExecutor: TaskExecutor;
    private readonly config: SentinelConfig;
    private readonly transportConfig: TransportConfig;
    private initialized = false;

    private constructor(config: SentinelConfig, options?: SentinelOptions) {
        this.config = config;
        this.transportConfig = options?.transport ?? { mode: "local" };

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
     * @param config SDK設定
     * @param options オプション（transport等）
     */
    public static initialize(config: SentinelConfig, options?: SentinelOptions): Sentinel {
        if (Sentinel.instance?.initialized) return Sentinel.instance;
        Sentinel.instance = new Sentinel(config, options);
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
     *
     * TransportMode に応じて処理先を切り替える:
     * - "local":  SDKローカルパイプライン（デフォルト）
     * - "remote": Goサーバにリモート送信（ローカル処理なし）
     * - "dual":   ローカル処理 + リモート送信の両方
     */
    public async ingest(log: Partial<Log>): Promise<IngestionResult> {
        // 入力検証（SDK公開API境界）
        validateLogInput(log);

        const mode = this.transportConfig.mode;

        if (mode === "remote" && this.transportConfig.transport) {
            try {
                const normalized = this.engine.normalizeOnly(log);
                return await this.transportConfig.transport.send(normalized);
            } catch (err) {
                if (this.transportConfig.fallbackToLocal) {
                    return this.engine.handle(log);
                }
                throw err;
            }
        }

        const localResult = await this.engine.handle(log);

        if (mode === "dual" && this.transportConfig.transport) {
            try {
                const normalized = this.engine.normalizeOnly(log);
                await this.transportConfig.transport.send(normalized);
            } catch {
                // dual mode: リモート失敗はローカル結果に影響しない
            }
        }

        return localResult;
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
export type { RemoteTransport, TransportMode, TransportConfig } from "./transport/transport";
export { validateLogInput, ValidationError } from "./validation/log-validator";
