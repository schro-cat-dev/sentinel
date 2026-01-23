import { BatchTransport } from "./batch-transport";
import { Log } from "../types/log";

export interface CloudWatchConfig {
    groupName: string;
    streamName: string;
    region: string;
}

export class CloudWatchTransport extends BatchTransport {
    public readonly name = "CloudWatch";

    constructor(private config: CloudWatchConfig) {
        // バッチサイズ 100件、インターバル 5秒
        super(100, 5000);
    }

    protected async processBatch(logs: Log[]): Promise<void> {
        // ここで AWS SDK 等を用いて実際に送信
        // JSON.stringify は IntegritySigner で作成した deterministic なものを使うのが望ましい
        const payload = logs.map((l) => ({
            message: JSON.stringify(l),
            timestamp: new Date(l.timestamp).getTime(),
        }));

        console.log(
            `[${this.name}] Delivering ${payload.length} logs to ${this.config.groupName}...`,
        );

        // 実際の SDK 呼び出しをシミュレート
        await Promise.resolve();
    }
}
