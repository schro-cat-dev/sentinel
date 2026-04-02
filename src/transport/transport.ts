import type { Log } from "../types/log";
import type { IngestionResult } from "../core/engine/types";

/**
 * Transport はログの送信先を抽象化するインターフェース。
 * ローカルパイプライン / gRPCサーバ / HTTP API 等を差し替え可能。
 *
 * SDKはzero-depのため、具体的なgRPC/HTTP実装は利用側が注入する。
 *
 * @example
 * ```typescript
 * // gRPC transport (利用側が @grpc/grpc-js を依存に追加)
 * const transport: RemoteTransport = {
 *   async send(log) {
 *     const client = new SentinelServiceClient(addr, credentials);
 *     const resp = await client.ingest(logToProto(log));
 *     return protoToResult(resp);
 *   },
 *   async healthCheck() {
 *     const resp = await client.healthCheck({});
 *     return resp.status === "SERVING";
 *   }
 * };
 * const sentinel = Sentinel.initialize(config, { transport });
 * ```
 */
export interface RemoteTransport {
    /**
     * ログをリモートサーバに送信する
     */
    send(log: Log): Promise<IngestionResult>;

    /**
     * サーバの生存確認
     */
    healthCheck?(): Promise<boolean>;

    /**
     * 接続を閉じる
     */
    close?(): Promise<void>;
}

/**
 * TransportMode はログ処理のモード
 */
export type TransportMode = "local" | "remote" | "dual";

/**
 * TransportConfig はTransportの設定
 */
export interface TransportConfig {
    /**
     * 処理モード
     * - "local":  SDKローカルパイプラインのみ（デフォルト）
     * - "remote": リモートサーバにのみ送信（ローカル処理なし）
     * - "dual":   ローカル処理 + リモート送信の両方
     */
    mode: TransportMode;

    /**
     * リモートTransport実装（mode が "remote" or "dual" の場合必須）
     */
    transport?: RemoteTransport;

    /**
     * リモート送信失敗時にローカル処理にフォールバックするか（mode="remote" 時のみ）
     */
    fallbackToLocal?: boolean;

    /**
     * リモート送信タイムアウト（ミリ秒）。デフォルト30000ms。
     */
    timeoutMs?: number;

    /**
     * サーキットブレーカー設定（R-4）
     * 連続失敗時にtransport送信を一時停止し、cooldown後に再試行する。
     */
    circuitBreaker?: {
        /** open に遷移するまでの連続失敗数（デフォルト: 5） */
        failureThreshold?: number;
        /** open 状態の冷却期間（ミリ秒、デフォルト: 30000） */
        cooldownMs?: number;
    };

    /**
     * TLS/mTLS設定（gRPC transport実装に渡す）
     * SDKはzero-depのため証明書の読み込み・接続はtransport実装側の責務。
     */
    tls?: {
        /** サーバCA証明書パス（自己署名証明書検証用） */
        caCertPath?: string;
        /** クライアント証明書パス（mTLS用） */
        clientCertPath?: string;
        /** クライアント秘密鍵パス（mTLS用） */
        clientKeyPath?: string;
    };
}
