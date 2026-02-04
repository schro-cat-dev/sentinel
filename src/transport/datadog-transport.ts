import { Log } from "../types/log";
import { BatchTransport } from "./batch-transport";

export interface DatadogConfig {
    apiKey: string;
    site: "datadoghq.com" | "datadoghq.eu";
}

export class DatadogTransport extends BatchTransport {
    public readonly name = "Datadog";

    constructor(private config: DatadogConfig) {
        super(50, 2000);
    }

    protected async processBatch(logs: Log[]): Promise<void> {
        // Log.level (0-6) → Datadog level文字列変換
        const levelMap: Record<number, string> = {
            0: "trace",
            1: "debug",
            2: "info",
            3: "warn",
            4: "error",
            5: "critical",
            6: "fatal",
        };

        const events = logs.map((log) => ({
            message: log.message,
            hostname: log.serviceId,
            level: levelMap[log.level] || "info", // フォールバック
            service: log.serviceId,
            ddsource: "sentinel",
            ddtags: `trace_id:${log.traceId},env:production,type:${log.type}`,
            timestamp: new Date(log.timestamp).getTime(),
            hash: log.hash, // 署名情報も改ざん検知用として送信
            signature: log.signature,
        }));

        const response = await fetch(
            `https://http-intake.logs.${this.config.site}/v1/input/${this.config.apiKey}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ logs: events }),
            },
        );

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Datadog ${response.status}: ${errorText}`);
        }

        console.log(
            `[${this.name}] Sent ${logs.length} logs (${events[0]?.level})`,
        );
    }
}
