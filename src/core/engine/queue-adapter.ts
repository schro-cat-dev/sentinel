import { WorkerPool } from "../../bootstrap/worker-pool";
import { GlobalConfig } from "../../configs/global-config";
import { Log } from "../../types/log";
import { IQueueAdapter } from "./i-interfaces";

export class QueueAdapter implements IQueueAdapter {
    constructor(
        private workerPool: WorkerPool,
        private gConfig: GlobalConfig,
    ) {}

    private readonly MAX_BACKOFF = 5000;
    private readonly MAX_ATTEMPTS = 10;

    async enqueueWithBackpressure(log: Log): Promise<void> {
        const { overflowStrategy } = this.gConfig.concurrency;

        switch (overflowStrategy) {
            case "BLOCK":
                await this.blockUntilAvailable();
                break;
            case "FAIL_FAST":
                if (this.isFull()) throw new Error("Queue full");
                break;
            case "DROP_LOW_PRIORITY":
                if (log.isCritical || log.level >= 5) {
                    await this.blockUntilAvailable();
                }
                break;
        }

        await this.workerPool.enqueue(log);
    }

    isFull(): boolean {
        return this.workerPool.isFull();
    }

    private async blockUntilAvailable(): Promise<void> {
        let backoff = 10;
        let attempts = 0;

        while (this.workerPool.isFull() && attempts < this.MAX_ATTEMPTS) {
            await new Promise((r) => setTimeout(r, backoff));
            backoff = Math.min(backoff * 2, this.MAX_BACKOFF);
            attempts++;
        }

        if (this.workerPool.isFull()) {
            throw new Error(
                `Queue backpressure timeout after ${this.MAX_ATTEMPTS} attempts`,
            );
        }
    }
}
