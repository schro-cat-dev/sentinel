import { SentinelConfig, createDefaultConfig } from "./configs/sentinel-config";
import { IngestionEngine } from "./core/engine/ingestion-engine";
import { LogNormalizer } from "./core/engine/log-normalizer";
import { MaskingService } from "./security/masking-service";
import { IntegritySigner } from "./security/integrity-signer";
import { EventDetector } from "./core/detection/event-detector";
import { TaskGenerator } from "./core/task/task-generator";
import { TaskExecutor, TaskDispatchHandler, TaskConfirmHandler } from "./core/task/task-executor";
import { Log } from "./types/log";
import { IngestionResult } from "./core/engine/types";
import { TransportConfig, RemoteTransport } from "./transport/transport";
import { validateLogInput, ValidationError } from "./validation/log-validator";
import { validateConfigWhitelists } from "./validation/config-validator";
import { WhitelistRegistry } from "./validation/whitelist-registry";

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
    private readonly whitelistRegistry?: WhitelistRegistry;
    private initialized = false;
    private isShutdown = false;

    private constructor(config: SentinelConfig, registry?: WhitelistRegistry, options?: SentinelOptions) {
        this.config = Sentinel.deepFreeze(config);
        this.whitelistRegistry = registry;
        this.transportConfig = options?.transport ?? { mode: "local" };

        const normalizer = new LogNormalizer(config.serviceId);
        const signer = new IntegritySigner();
        const detector = new EventDetector(config.detectionRules);
        const taskGenerator = new TaskGenerator(config.taskRules);
        this.taskExecutor = new TaskExecutor();

        this.engine = new IngestionEngine({
            config,
            normalizer,
            signer,
            detector,
            taskGenerator,
            taskExecutor: this.taskExecutor,
        });

        this.initialized = true;
    }

    /**
     * Sentinel を初期化（シングルトン）
     * 既に初期化済みの場合は既存インスタンスを返し、警告を出す。
     */
    public static initialize(config: SentinelConfig, options?: SentinelOptions): Sentinel {
        if (Sentinel.instance?.initialized) {
            const logger = config.logger ?? Sentinel.instance.config.logger;
            logger?.warn("Sentinel.initialize() called but already initialized. Returning existing instance. Call Sentinel.reset() or shutdown() first to re-initialize.", { source: "sentinel" });
            return Sentinel.instance;
        }
        const { registry } = validateConfigWhitelists(config);
        Sentinel.instance = new Sentinel(config, registry, options);
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
     * 非テスト環境で呼ばれた場合は警告を出す。
     */
    public static reset(): void {
        if (Sentinel.instance) {
            const env = Sentinel.instance.config.environment;
            if (env !== "test" && env !== "local") {
                Sentinel.instance.config.logger?.warn(
                    `Sentinel.reset() called in "${env}" environment. This method is intended for testing only.`,
                    { source: "sentinel" },
                );
            }
            // リソースクリーンアップ（非同期closeはbest-effort）
            try { Sentinel.instance.transportConfig.transport?.close?.(); } catch { /* */ }
            Sentinel.instance.taskExecutor.clearHandlers();
            Sentinel.instance.engine.resetState();
        }
        Sentinel.instance = null;
    }

    /**
     * グレースフルシャットダウン
     * Transport接続を閉じ、インスタンスをクリアする。
     */
    public async shutdown(): Promise<void> {
        if (this.isShutdown) return;
        this.isShutdown = true;

        try {
            await this.transportConfig.transport?.close?.();
        } catch {
            // transport close errors are best-effort
        }
        this.taskExecutor.clearHandlers();
        this.engine.resetState();
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
        if (this.isShutdown) throw new Error("Sentinel is shutdown. Cannot ingest after shutdown.");
        validateLogInput(log, this.config.validationLimits);

        const mode = this.transportConfig.mode;

        if (mode === "remote" && this.transportConfig.transport) {
            try {
                const normalized = this.engine.normalizeOnly(log);
                return await this.sendWithTimeout(normalized);
            } catch (err) {
                if (this.transportConfig.fallbackToLocal) {
                    return this.engine.handle(log);
                }
                throw err;
            }
        }

        const localResult = await this.engine.handle(log);

        if (mode === "dual" && this.transportConfig.transport) {
            // RES-02: ローカル処理済みログを再利用し、2度目の正規化を回避
            try {
                await this.sendWithTimeout(this.engine.getLastProcessedLog()!);
            } catch (e) {
                const error = e instanceof Error ? e : new Error(String(e));
                localResult.transportError = error.message;
                try { this.engine.getOnError()?.(error, "transport.dual"); } catch { /* */ }
            }
        }

        return localResult;
    }

    /**
     * タスクアクションハンドラの登録。
     * 戻り値の関数を呼ぶとこのハンドラのみ解除される。
     */
    public onTaskAction(actionType: string, handler: TaskDispatchHandler): () => void {
        if (this.isShutdown) throw new Error("Sentinel is shutdown. Cannot register handler after shutdown.");
        this.whitelistRegistry?.validate("actionType", actionType);
        this.taskExecutor.registerHandler(actionType, handler);
        this.warnIfTooManyHandlers(actionType);
        return () => this.taskExecutor.unregisterHandler(actionType, handler);
    }

    private warnIfTooManyHandlers(actionType: string): void {
        const MAX_HANDLERS_PER_ACTION = 10;
        const count = this.taskExecutor.getHandlerCount(actionType);
        if (count > MAX_HANDLERS_PER_ACTION) {
            this.config.logger?.warn(
                `${count} handlers registered for actionType "${actionType}". This may indicate a leak. Use removeHandlers() to clean up.`,
                { source: "sentinel" },
            );
        }
    }

    /**
     * SEMI_AUTO タスクの確認ハンドラを設定
     * handler が false を返すと blocked_approval になる
     */
    public onTaskConfirm(handler: TaskConfirmHandler): void {
        this.taskExecutor.setConfirmHandler(handler);
    }

    /**
     * 現在の設定を取得
     */
    public getConfig(): Readonly<SentinelConfig> {
        return this.config;
    }

    /**
     * ライフサイクルコールバックを動的に更新する。
     *
     * configはdeepFreezeされているが、コールバックは運用中に差し替えが必要な場合がある
     * （例: ログ出力先の変更、メトリクス収集の切替）。
     * この関数はエンジン内部のコールバック参照を安全に更新する。
     *
     * @param callbacks 更新するコールバック（省略されたフィールドは変更しない）
     */
    public updateCallbacks(callbacks: {
        onLogProcessed?: ((log: Log) => void) | null;
        onTaskGenerated?: ((task: import("./types/task").GeneratedTask) => void) | null;
        onTaskDispatched?: ((result: import("./types/task").TaskResult) => void) | null;
        onError?: ((error: Error, context: string) => void) | null;
    }): void {
        if (this.isShutdown) throw new Error("Sentinel is shutdown. Cannot update callbacks after shutdown.");
        this.engine.updateCallbacks(callbacks);
    }

    /**
     * 設定オブジェクトをdeep freezeして外部からの変更を防ぐ
     */
    private static deepFreeze<T extends object>(obj: T): T {
        Object.freeze(obj);
        for (const value of Object.values(obj)) {
            if (value && typeof value === "object" && !Object.isFrozen(value)) {
                Sentinel.deepFreeze(value as object);
            }
        }
        return obj;
    }

    /**
     * Transport送信 + タイムアウト
     */
    private async sendWithTimeout(log: Log): Promise<IngestionResult> {
        const transport = this.transportConfig.transport!;
        const timeoutMs = this.transportConfig.timeoutMs ?? 30_000;

        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
            const sendPromise = transport.send(log);
            const timeoutPromise = new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error(`Transport timeout after ${timeoutMs}ms`)), timeoutMs);
            });
            return await Promise.race([sendPromise, timeoutPromise]);
        } finally {
            if (timer !== undefined) clearTimeout(timer);
        }
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
export type { SystemEventName, DetectionResult, DetectionRule, DetectionRuleConditions } from "./types/event";
export type { TaskDispatchHandler, TaskConfirmHandler } from "./core/task/task-executor";
export type { SentinelLogger, SentinelMetrics, SentinelTracer } from "./configs/sentinel-config";
export type { RemoteTransport, TransportMode, TransportConfig } from "./transport/transport";
export { validateLogInput, ValidationError, DEFAULT_VALIDATION_LIMITS } from "./validation/log-validator";
export type { ValidationLimits } from "./validation/log-validator";
export { WhitelistRegistry } from "./validation/whitelist-registry";
export { validateConfigWhitelists } from "./validation/config-validator";
export type { WhitelistDefinition, WhitelistExtensions } from "./validation/whitelist-types";
export type { WhitelistDomain, WhitelistLevel, WhitelistValidationResult } from "./validation/config-validator";
