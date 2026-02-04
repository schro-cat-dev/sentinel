import { Log } from "../types/log";
import { BatchTransport } from "./batch-transport";

export interface HttpTransportConfig {
    endpoint: string;
    apiKey?: string;
    batchSize?: number;
    timeoutMs?: number;
}

export class HttpTransport extends BatchTransport {
    public readonly name = "HTTP";

    constructor(private config: HttpTransportConfig) {
        super(config.batchSize ?? 50, 3000);
    }

    protected async processBatch(logs: Log[]): Promise<void> {
        const response = await fetch(this.config.endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${this.config.apiKey}`,
                "X-Log-Count": logs.length.toString(),
            },
            body: JSON.stringify({
                logs,
                batchSize: logs.length,
                timestamp: new Date().toISOString(),
            }),
            signal: AbortSignal.timeout(this.config.timeoutMs ?? 10000),
        });

        if (!response.ok) {
            const error = new Error(
                `HTTP ${response.status}: ${await response.text()}`,
            );
            throw error;
        }

        console.log(
            `[${this.name}] Sent ${logs.length} logs to ${this.config.endpoint} (${response.status})`,
        );
    }
}
