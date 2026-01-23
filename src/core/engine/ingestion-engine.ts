import { randomUUID } from "crypto"; // 修正: randomUUIDを直接インポート
import { Log } from "../../types/log";
import { GlobalConfig } from "../../configs/global-config"; // パス修正
import { WALManager } from "../persistence/wal-manager";
import { WorkerPool } from "../../bootstrap/worker-pool";
import { ITaskRepository } from "../../intelligence/task/i-task-repository";

export class IngestionEngine {
    constructor(
        private gConfig: GlobalConfig,
        private wal: WALManager,
        private workerPool: WorkerPool,
        private taskRepo: ITaskRepository,
    ) {
        // 起動時にWALから未送信ログを復旧
        this.recoverUnsentLogs().catch((err) =>
            console.error("[IngestionEngine] Recovery failed:", err),
        );
    }

    private async recoverUnsentLogs(): Promise<void> {
        const pendingLogs = await this.wal.recover();
        if (pendingLogs.length > 0) {
            for (const log of pendingLogs) {
                await this.workerPool.enqueue(log);
            }
            await this.wal.truncate();
        }
    }

    public async handle(raw: Partial<Log>): Promise<void> {
        const log: Log = {
            traceId: raw.traceId || randomUUID(), // 修正済み
            type: raw.type || "SYSTEM",
            level: raw.level || 3,
            timestamp: new Date().toISOString(),
            logicalClock: Date.now(),
            boundary: raw.boundary || "unknown",
            serviceId: this.gConfig.serviceId,
            isCritical: raw.isCritical || false,
            message: raw.message || "",
            origin: raw.origin || "SYSTEM",
            triggerAgent: raw.triggerAgent || false,
            tags: raw.tags || [],
            // 初期化時は agentBackLog なし（WorkerまたはAIが後続で付与）
            ...raw,
        } as Log;

        // 1. WALへの書き込み（最優先：クラッシュ対策）
        if (this.gConfig.persistence.enabled) {
            await this.wal.append(log);
        }

        // 2. Worker Pool へのディスパッチ（背圧制御付き）
        try {
            await this.enqueueWithBackpressure(log);
        } catch (e) {
            this.handleOverflow(log, e);
        }
    }

    /**
     * 背圧制御ロジックの実装
     */
    private async enqueueWithBackpressure(log: Log): Promise<void> {
        const { overflowStrategy } = this.gConfig.concurrency;

        if (overflowStrategy === "BLOCK") {
            // キューが空くまで待機するループ（簡易版）
            // 実際には WorkerPool が emit する 'drain' イベントを待機する設計が理想
            while (this.workerPool.isFull()) {
                await new Promise((resolve) => setTimeout(resolve, 10)); // 10ms待機
            }
        }

        await this.workerPool.enqueue(log);
    }

    private handleOverflow(log: Log, error: unknown): void {
        const strategy = this.gConfig.concurrency.overflowStrategy;

        // クリティカルなログは、DROP設定であってもエラーログとして標準出力に残すべき（金融要件）
        if (log.isCritical || log.level >= 5) {
            console.error(
                "[IngestionEngine] CRITICAL LOG OVERFLOW:",
                JSON.stringify(log),
            );
        }

        if (strategy === "FAIL_FAST") {
            throw new Error(
                `Log queue overflow: ${error instanceof Error ? error.message : String(error)}`,
            );
        }
        // DROP_LOW_PRIORITY の場合はサイレントに終了
    }
}
