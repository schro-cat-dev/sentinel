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
}
