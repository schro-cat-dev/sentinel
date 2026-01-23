import { ILogTransport } from "./i-log-transport";
import { Log } from "../types/log";

export class TransportManager {
    private transports: ILogTransport[] = [];

    public addTransport(transport: ILogTransport): void {
        this.transports.push(transport);
    }

    /**
     * Worker で加工が終わったログを各トランスポートへ分配
     */
    public async broadcast(log: Log): Promise<void> {
        // 全てのトランスポートに対して並列で送信を開始
        // 一つの送信エラーが他の送信を妨げないよう Promise.allSettled を検討
        const deliveries = this.transports.map((t) =>
            t
                .send(log)
                .catch((err) =>
                    console.error(
                        `[TransportManager] Fatal error in transport ${t.name}:`,
                        err,
                    ),
                ),
        );

        await Promise.all(deliveries);
    }

    public async shutdown(): Promise<void> {
        console.log(
            "[TransportManager] Flushing all buffers before shutdown...",
        );
        await Promise.all(this.transports.map((t) => t.flush()));
    }
}
