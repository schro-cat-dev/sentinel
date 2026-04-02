import type { TaskTransportConfig } from "../configs/sentinel-config";
import type { TaskTransport } from "./task-transport";
import { ConsoleTaskTransport } from "./console-task-transport";
import { HttpWebhookTransport } from "./http-webhook-transport";

/**
 * TaskTransportConfig 配列から組み込みトランスポートインスタンスを生成する。
 *
 * - `enabled: false` のエントリはスキップ
 * - `type: "http_webhook"` → HttpWebhookTransport
 * - `type: "console"` → ConsoleTaskTransport
 * - `type: "custom"` / undefined → スキップ（利用者が SentinelOptions.taskTransports で注入）
 *
 * @param configs YAML等から読み込まれた TaskTransportConfig 配列
 * @returns 生成された TaskTransport インスタンスの配列
 */
export function createTaskTransportsFromConfig(
    configs: readonly TaskTransportConfig[],
): TaskTransport[] {
    const transports: TaskTransport[] = [];

    for (const config of configs) {
        // enabled=false はスキップ（デフォルトは true）
        if (config.enabled === false) continue;

        switch (config.type) {
            case "http_webhook":
                transports.push(new HttpWebhookTransport({
                    name: config.name,
                    endpoint: config.endpoint!,
                    headers: config.headers,
                    method: config.method as "POST" | "PUT" | undefined,
                    allowInsecure: config.allow_insecure === true,
                }));
                break;

            case "console":
                transports.push(new ConsoleTaskTransport(config.name));
                break;

            case "custom":
            default:
                // custom / undefined: 利用者が SentinelOptions.taskTransports で注入
                break;
        }
    }

    return transports;
}
