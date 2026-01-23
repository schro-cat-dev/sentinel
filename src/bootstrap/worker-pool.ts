import { Worker } from "node:worker_threads"; // node: プレフィックス推奨らしいので残す。
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { GlobalConfig } from "../configs/global-config";
import { Log } from "../types/log";
import { WorkerToMainMessage } from "../types/event";
import { DetailedConfig } from "../configs/detailed-config";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export class WorkerPool extends EventEmitter {
    private workers: (Worker | null)[] = [];
    private nextWorkerIndex = 0;
    private isShuttingDown = false;
    private readonly workerPath: string;

    private activeTaskCount = 0; // 現在実行中（またはキュー滞留中）のタスク数

    constructor(
        private gConfig: GlobalConfig,
        private dConfig: DetailedConfig,
    ) {
        super();
        // 実行環境（TS/JS）に応じたパス解決
        this.workerPath = join(__dirname, "../workers/log.worker.js");
    }

    /**
     * 初期ブート処理
     */
    public async boot(): Promise<void> {
        const workerCount = this.gConfig.concurrency.workerCount;
        console.log(`[WorkerPool] Booting ${workerCount} workers...`);

        const bootPromises = Array.from({ length: workerCount }).map((_, i) =>
            this.spawnWorker(i),
        );
        await Promise.all(bootPromises);

        console.log("[WorkerPool] All workers are online.");
    }

    /**
     * 現在の負荷状況を確認
     * 計算式: $ActiveTasks \ge MaxQueueSize$
     */
    public isFull(): boolean {
        return this.activeTaskCount >= this.gConfig.concurrency.maxQueueSize;
    }

    /**
     * Worker からのメッセージ処理
     */
    private handleWorkerMessage(message: WorkerToMainMessage): void {
        // 処理完了通知（LOG_PROCESSED または ERROR 等）を受け取った場合
        if (message.type === "LOG_PROCESSED" || message.type === "ERROR") {
            this.activeTaskCount--;

            // 背圧の解消を通知
            // 「満杯」の状態から空きができた瞬間にのみ drain を発火
            if (
                this.activeTaskCount ===
                this.gConfig.concurrency.maxQueueSize - 1
            ) {
                this.emit("drain");
            }
        }
    }

    /**
     * Worker の生成とイベントハンドリングの集約
     */
    private async spawnWorker(index: number): Promise<void> {
        return new Promise((resolve, reject) => {
            const worker = new Worker(this.workerPath, {
                workerData: {
                    gConfig: this.gConfig,
                    dConfig: this.dConfig,
                },
            });

            worker.on("message", (message: WorkerToMainMessage) => {
                this.handleWorkerMessage(message);
                this.emit(message.type, message.payload);
            });

            worker.on("error", (err) => {
                console.error(`[WorkerPool] Worker[${index}] error:`, err);
                if (!this.isShuttingDown) this.replaceWorker(index);
            });

            worker.on("exit", (code) => {
                if (code !== 0 && !this.isShuttingDown) {
                    console.error(
                        `[WorkerPool] Worker[${index}] exited with code ${code}`,
                    );
                    this.replaceWorker(index);
                }
            });

            worker.on("online", () => {
                this.workers[index] = worker;
                resolve();
            });

            // タイムアウト監視
            setTimeout(
                () => reject(new Error(`Worker[${index}] boot timeout`)),
                10000,
            );
        });
    }

    /**
     * 自己修復ロジック：死んだ Worker を破棄し、新しい Worker を同じインデックスに配置
     */
    private async replaceWorker(index: number): Promise<void> {
        if (this.isShuttingDown) return;

        console.warn(
            `[WorkerPool] Self-healing: Replacing worker at index ${index}`,
        );

        // 既存の Worker があれば強制終了
        const oldWorker = this.workers[index];
        if (oldWorker) {
            oldWorker.terminate().catch(() => {});
            this.workers[index] = null;
        }

        try {
            // 指数バックオフなどでリトライ（普通にシステムやサーバプロセスレベルで疎結合・非同期化してましに扱えるように。その部分の接続中間層も扱えるように。）
            await this.spawnWorker(index);
            console.log(`[WorkerPool] Successfully replaced worker[${index}]`);
        } catch (err) {
            console.error(
                `[WorkerPool] Failed to replace worker[${index}]:`,
                err,
            );
            // 再試行をスケジュール
            setTimeout(() => this.replaceWorker(index), 5000);
        }
    }

    /**
     * ラウンドロビンによるディスパッチ
     */
    public async enqueue(log: Log): Promise<void> {
        if (this.isShuttingDown) return;

        // 生存している Worker を探す
        let attempts = 0;
        while (attempts < this.workers.length) {
            const worker = this.workers[this.nextWorkerIndex];
            this.nextWorkerIndex =
                (this.nextWorkerIndex + 1) % this.workers.length;

            if (worker) {
                // タスク投入時カウント
                this.activeTaskCount++;
                worker.postMessage({ type: "PROCESS_LOG", payload: log });
                return;
            }
            attempts++;
        }

        throw new Error(
            "[WorkerPool] No healthy workers available to process log.",
        );
    }

    public async shutdown(): Promise<void> {
        this.isShuttingDown = true;
        console.log("[WorkerPool] Shutting down all workers...");

        const terminations = this.workers.map((w) => w?.terminate());
        await Promise.all(terminations);

        this.workers = [];
        this.removeAllListeners();
        console.log("[WorkerPool] Shutdown complete.");
    }
}
