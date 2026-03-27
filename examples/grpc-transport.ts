/**
 * Sentinel SDK → Go Server gRPC Transport 実装例
 *
 * 利用するには @grpc/grpc-js と @grpc/proto-loader を依存に追加:
 *   npm install @grpc/grpc-js @grpc/proto-loader
 *
 * 使い方:
 *   import { Sentinel, createDefaultConfig } from "@schro-cat-dev/sentinel";
 *   import { createGrpcTransport } from "./grpc-transport";
 *
 *   const transport = createGrpcTransport("localhost:50051");
 *   const sentinel = Sentinel.initialize(config, {
 *     transport: { mode: "dual", transport }
 *   });
 */

import type { RemoteTransport } from "../src/transport/transport";
import type { IngestionResult } from "../src/core/engine/types";
import type { Log } from "../src/types/log";

/**
 * gRPC Transport を生成する
 *
 * @param serverAddr - Sentinel Go サーバのアドレス (e.g., "localhost:50051")
 * @param apiKey - 認証用APIキー（省略可）
 *
 * @example
 * ```typescript
 * const transport = createGrpcTransport("localhost:50051", "my-api-key");
 * const sentinel = Sentinel.initialize(config, {
 *   transport: { mode: "remote", transport, fallbackToLocal: true }
 * });
 * ```
 */
export function createGrpcTransport(serverAddr: string, apiKey?: string): RemoteTransport {
    // 注意: この実装は @grpc/grpc-js が必要です
    // SDK本体はzero-depのため、gRPC依存はここに閉じています

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const grpc = require("@grpc/grpc-js");
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const protoLoader = require("@grpc/proto-loader");

    const PROTO_PATH = require("path").resolve(__dirname, "../packages/server/proto/sentinel.proto");

    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
        keepCase: false,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const SentinelService = (protoDescriptor.sentinel as Record<string, unknown>).v1 as Record<string, unknown>;
    const ServiceClient = SentinelService.SentinelService as typeof grpc.Client;

    const metadata = new grpc.Metadata();
    if (apiKey) {
        metadata.set("x-api-key", apiKey);
    }

    const client = new ServiceClient(serverAddr, grpc.credentials.createInsecure());

    return {
        async send(log: Log): Promise<IngestionResult> {
            const request = {
                traceId: log.traceId,
                type: log.type,
                level: log.level,
                boundary: log.boundary,
                serviceId: log.serviceId,
                isCritical: log.isCritical,
                message: log.message,
                origin: log.origin,
                actorId: log.actorId || "",
                spanId: log.spanId || "",
                parentSpanId: log.parentSpanId || "",
                tags: (log.tags || []).map((t) => ({ key: t.key, category: t.category })),
                resourceIds: log.resourceIds || [],
                input: typeof log.input === "string" ? log.input : "",
                triggerAgent: log.triggerAgent || false,
            };

            return new Promise<IngestionResult>((resolve, reject) => {
                client.Ingest(request, metadata, (err: Error | null, response: Record<string, unknown>) => {
                    if (err) {
                        reject(new Error(`gRPC error: ${err.message}`));
                        return;
                    }
                    resolve({
                        traceId: response.traceId as string,
                        hashChainValid: response.hashChainValid as boolean,
                        masked: response.masked as boolean,
                        tasksGenerated: (response.tasksGenerated as Array<Record<string, unknown>> || []).map((t) => ({
                            taskId: t.taskId as string,
                            ruleId: t.ruleId as string,
                            status: t.status as string,
                            dispatchedAt: t.dispatchedAt as string,
                            error: (t.error as string) || undefined,
                        })),
                    });
                });
            });
        },

        async healthCheck(): Promise<boolean> {
            return new Promise((resolve) => {
                client.HealthCheck({}, metadata, (err: Error | null, response: Record<string, unknown>) => {
                    if (err) {
                        resolve(false);
                        return;
                    }
                    resolve(response.status === "SERVING");
                });
            });
        },

        async close(): Promise<void> {
            client.close();
        },
    };
}
