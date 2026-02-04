import { ILogTransport } from "./i-log-transport";
import { Log } from "../types/log";

export abstract class BatchTransport implements ILogTransport {
    public abstract readonly name: string;
    private buffer: Log[] = [];
    private timer: NodeJS.Timeout | null = null;

    constructor(
        protected readonly batchSize: number,
        protected readonly flushIntervalMs: number,
    ) {}

    public async send(log: Log): Promise<void> {
        this.buffer.push(log);

        if (this.buffer.length >= this.batchSize) {
            await this.flush();
        } else if (!this.timer) {
            this.timer = setTimeout(() => this.flush(), this.flushIntervalMs);
        }
    }

    public async flush(): Promise<void> {
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        if (this.buffer.length === 0) return;

        // バッファをコピーして即座に空に
        const batchToSend = [...this.buffer];
        this.buffer = [];

        // TODO 他の箇所ではこのTODOは省略するが src/shared/functional/のものを利用して一元化。さらに後フェーズで連携周り。
        try {
            await this.processBatch(batchToSend);
        } catch (error) {
            // 送信失敗時のリトライロジック（イベント情報または情報保全の関係でここでデッドレターキューに回す。マルチノードまたはDS、クラウド、等）
            console.error(
                `[Transport:${this.name}] Batch delivery failed:`,
                error,
            );
            // 必要に応じてバッファに書き戻す、またはセカンダリストレージへ退避
        }
    }

    /**
     * 各アダプター（CloudWatch/Postフェーズ等）で実装する具象メソッド
     */
    protected abstract processBatch(logs: Log[]): Promise<void>;
}
