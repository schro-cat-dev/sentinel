import { DIContainer } from "./bootstrap/di-container";
import { WorkerPool } from "./bootstrap/worker-pool";
import { DetailedConfig } from "./configs/detailed-config";
import { GlobalConfig } from "./configs/global-config";
import { IngestionEngine } from "./core/engine/ingestion-engine";
import { Log } from "./types/log";

// TODO ai-intelligence周り + 他細微な内部調整、確認が終わってから調整
export class Logger {
    private static instance: Logger;
    private engine!: IngestionEngine;
    private workerPool!: WorkerPool;
    private initialized = false;

    private constructor() {}

    public static async initialize(
        gConfig: GlobalConfig,
        dConfig: DetailedConfig,
    ): Promise<Logger> {
        if (this.instance?.initialized) return this.instance;

        const logger = new Logger();
        const diContainer = new DIContainer(gConfig, dConfig);

        await diContainer.init();

        logger.engine = diContainer.resolve<IngestionEngine>("IngestionEngine");
        logger.workerPool = diContainer.resolve<WorkerPool>("WorkerPool");
        logger.initialized = true;

        this.instance = logger;
        console.log(
            `[Logger] Successfully initialized for project: ${gConfig.projectName}`,
        );
        return this.instance;
    }

    public static getInstance(): Logger {
        if (!this.instance) throw new Error("Logger must be initialized first");
        return this.instance;
    }

    /**
     * ログ投入
     */
    public async ingest(log: Partial<Log>): Promise<void> {
        return this.engine.handle(log);
    }

    /**
     * 正常終了処理
     * 全ての Worker を停止し、仕掛かり中のログを保護する
     */
    public async shutdown(): Promise<void> {
        console.log("[Logger] Initiating graceful shutdown...");

        // 1. WorkerPool の停止（処理中のタスク完了を待機）
        await this.workerPool.shutdown();

        // 2. 必要に応じて Transport のフラッシュ（TransportManager がある場合）

        this.initialized = false;
        console.log("[Logger] Shutdown complete.");
    }
}

// 型のエクスポート
export * from "./types/log";
export * from "./configs/global-config";
export * from "./configs/detailed-config";
