import type { GeneratedTask } from "../types/task";
import type { TaskTransport, TaskTransportResult } from "./task-transport";

/**
 * HttpWebhookTransport の初期化オプション
 */
export interface HttpWebhookTransportOptions {
    /** トランスポート識別名（デフォルト: "http_webhook"） */
    name?: string;
    /** Webhook エンドポイント URL（必須） */
    endpoint: string;
    /** HTTP ヘッダー（Content-Type のデフォルトは application/json） */
    headers?: Record<string, string>;
    /** HTTP メソッド（デフォルト: "POST"） */
    method?: "POST" | "PUT";
    /**
     * 開発/テスト用: HTTP スキームとプライベート IP を許可する。
     * 本番環境では false (デフォルト) を維持すること。
     */
    allowInsecure?: boolean;
}

/**
 * SSRF 防御用のプライベート IP パターン。
 * F-05 (Webhook SSRF) の脅威モデルに対応。
 */
const PRIVATE_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

function isPrivateIp(hostname: string): boolean {
    if (PRIVATE_HOSTNAMES.has(hostname)) return true;
    // 10.x.x.x
    if (/^10\./.test(hostname)) return true;
    // 172.16.0.0 - 172.31.255.255
    const m172 = hostname.match(/^172\.(\d+)\./);
    if (m172 && +m172[1] >= 16 && +m172[1] <= 31) return true;
    // 192.168.x.x
    if (/^192\.168\./.test(hostname)) return true;
    // 169.254.x.x (link-local)
    if (/^169\.254\./.test(hostname)) return true;
    return false;
}

/**
 * HTTP Webhook 組み込みトランスポート。
 *
 * Node.js 20+ の built-in fetch を使用（zero-dep）。
 * SSRF 防御（F-05）: デフォルトで HTTPS のみ、プライベート IP を拒否。
 *
 * YAML 設定の `type: "http_webhook"` で自動生成される。
 *
 * @example
 * ```typescript
 * const transport = new HttpWebhookTransport({
 *     endpoint: "https://hooks.slack.com/services/xxx",
 *     headers: { "Content-Type": "application/json" },
 * });
 * ```
 */
export class HttpWebhookTransport implements TaskTransport {
    public readonly name: string;
    private readonly endpoint: string;
    private readonly headers: Record<string, string>;
    private readonly method: "POST" | "PUT";
    private closed = false;
    private readonly abortController = new AbortController();

    constructor(options: HttpWebhookTransportOptions) {
        this.name = options.name ?? "http_webhook";
        this.method = options.method ?? "POST";
        this.endpoint = options.endpoint;

        // URL バリデーション
        let parsed: URL;
        try {
            parsed = new URL(options.endpoint);
        } catch {
            throw new Error(`[${this.name}] Invalid endpoint URL: "${options.endpoint}"`);
        }

        if (!options.allowInsecure) {
            if (parsed.protocol !== "https:") {
                throw new Error(
                    `[${this.name}] Endpoint must use HTTPS (got "${parsed.protocol}"). ` +
                    `Set allowInsecure: true for development/testing.`,
                );
            }
            if (isPrivateIp(parsed.hostname)) {
                throw new Error(
                    `[${this.name}] Endpoint must not be a private/loopback address (got "${parsed.hostname}"). ` +
                    `Set allowInsecure: true for development/testing.`,
                );
            }
        }

        // ヘッダー: デフォルト + ユーザー指定（ユーザーが勝つ）
        this.headers = {
            "Content-Type": "application/json",
            ...options.headers,
        };
    }

    async dispatch(task: GeneratedTask): Promise<TaskTransportResult> {
        if (this.closed) {
            return {
                transportName: this.name,
                success: false,
                error: `[${this.name}] transport is closed`,
            };
        }

        const response = await fetch(this.endpoint, {
            method: this.method,
            headers: this.headers,
            body: JSON.stringify(task),
            signal: this.abortController.signal,
        });

        if (!response.ok) {
            return {
                transportName: this.name,
                success: false,
                error: `[${this.name}] HTTP ${response.status}`,
            };
        }

        return {
            transportName: this.name,
            success: true,
        };
    }

    async close(): Promise<void> {
        this.closed = true;
        this.abortController.abort();
    }
}
