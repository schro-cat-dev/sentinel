import { WorkerPool } from "../../bootstrap/worker-pool";
import { GlobalConfig } from "../../configs/global-config";
import { Log } from "../../types/log";
import { WALManager } from "../../infrastructure/persistence/wal-manager";
import {
    ILoggerNormalizer,
    IPersistenceLayer,
    IQueueAdapter,
    IRecoveryService,
} from "./i-interfaces";
import { LogNormalizer } from "./log-normalizer";
import { PersistenceLayer } from "./persistence-layer";
import { QueueAdapter } from "./queue-adapter";
import { RecoveryService } from "./recovery-service";
import { IngestionResult } from "./types";

export interface IIngestionCoordinator {
    handle(raw: Partial<Log>): Promise<IngestionResult>;
}

export class IngestionEngine implements IIngestionCoordinator {
    private readonly normalizer: ILoggerNormalizer;
    private readonly persistence: IPersistenceLayer;
    private readonly queue: IQueueAdapter;
    private readonly recovery: IRecoveryService;
    private readonly gConfig: GlobalConfig;

    constructor(deps: {
        gConfig: GlobalConfig;
        wal: WALManager;
        workerPool: WorkerPool;
        // taskRepo: ITaskRepository;
    }) {
        this.gConfig = deps.gConfig;

        this.normalizer = new LogNormalizer(deps.gConfig);
        this.persistence = new PersistenceLayer(deps.wal);
        this.queue = new QueueAdapter(deps.workerPool, deps.gConfig);
        this.recovery = new RecoveryService(this.persistence, this.queue);

        // 復旧処理を非同期起動（メイン処理と分離）
        this.recovery
            .recoverUnsentLogs()
            .catch((err) =>
                console.error("[IngestionEngine] Recovery failed:", err),
            );
    }

    async handle(raw: Partial<Log>): Promise<IngestionResult> {
        const log = this.normalizer.normalize(raw);

        const [persistResult, dispatchResult] = await Promise.allSettled([
            this.persistence.append(log),
            this.queue.enqueueWithBackpressure(log),
        ]);

        // オーバーフロー処理
        let overflowHandled = false;
        if (dispatchResult.status === "rejected") {
            this.handleOverflow(log, dispatchResult.reason);
            overflowHandled = true;
        }

        return {
            traceId: log.traceId,
            persisted: persistResult.status === "fulfilled",
            dispatched: dispatchResult.status === "fulfilled",
            overflowHandled,
        };
    }

    /**
     * オーバーフロー専用ハンドラ
     */
    private handleOverflow(log: Log, error: unknown): void {
        const strategy = this.gConfig.concurrency.overflowStrategy;

        // クリティカルログは強制出力（金融要件志向）
        if (log.isCritical || log.level >= 5) {
            console.error(
                "[IngestionEngine] CRITICAL LOG OVERFLOW:",
                JSON.stringify(log),
            );
        }

        if (strategy === "FAIL_FAST") {
            const errMsg = `Log queue overflow: ${
                error instanceof Error ? error.message : String(error)
            }`;
            throw new Error(errMsg);
        }
        // TODO DROP_LOW_PRIORITYはサイレントドロップなので要改修
    }
}

export const createIngestionEngine = (deps: {
    gConfig: GlobalConfig;
    wal: WALManager;
    workerPool: WorkerPool;
    // taskRepo: ITaskRepository;
}): IIngestionCoordinator => {
    return new IngestionEngine(deps);
};
