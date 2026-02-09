// NOTE: UIで表示するようのラベルについてはこれは内部的なログでユーザに送ってしまうとセキュリティリスクになるので回避。

/**
 * システム構成要素・エラー発生箇所の完全分類(詳細証跡監査用)
 */
export const ERROR_LAYERS = {
    // --- UI/クライアント層 ---
    UI_RENDERER: "ui-renderer" as const,
    UI_STATE_MANAGER: "ui-state-manager" as const,
    UI_FORM_HANDLER: "ui-form-handler" as const,
    UI_API_CALLER: "ui-api-caller" as const,
    UI_VALIDATOR: "ui-validator" as const,

    // --- プレゼンテーション層（エントリーポイント） ---
    HTTP_CONTROLLER: "http-controller" as const,
    GRAPHQL_RESOLVER: "graphql-resolver" as const,
    GRPC_HANDLER: "grpc-handler" as const,
    WEBSOCKET_HANDLER: "websocket-handler" as const,
    SSE_HANDLER: "sse-handler" as const,
    CLI_COMMAND: "cli-command" as const,

    // --- アプリケーション層（ビジネスロジックオーケストレーション） ---
    APPLICATION_SERVICE: "application-service" as const,
    USE_CASE: "use-case" as const,
    COMMAND_HANDLER: "command-handler" as const,
    EVENT_HANDLER: "event-handler" as const,

    // --- ドメイン層（コアビジネスロジック） ---
    DOMAIN_SERVICE: "domain-service" as const,
    ENTITY_METHOD: "entity-method" as const,
    AGGREGATE_METHOD: "aggregate-method" as const,

    // --- データアクセス層 ---
    REPOSITORY: "repository" as const,
    REPOSITORY_QUERY: "repository-query" as const,
    REPOSITORY_MUTATE: "repository-mutate" as const,
    DAO: "dao" as const,
    ORM_OPERATION: "orm-operation" as const,

    // --- インフラ連携層（外部依存） ---
    HTTP_CLIENT: "http-client" as const,
    GRPC_CLIENT: "grpc-client" as const,
    MESSAGE_QUEUE_PRODUCER: "message-queue-producer" as const,
    MESSAGE_QUEUE_CONSUMER: "message-queue-consumer" as const,
    CACHE_OPERATION: "cache-operation" as const,
    SEARCH_CLIENT: "search-client" as const,
    FILE_STORAGE: "file-storage" as const,

    // --- 基盤機能（横断的） ---
    MIDDLEWARE: "middleware" as const,
    VALIDATOR: "validator" as const,
    SERIALIZER: "serializer" as const,
    AUTH_GUARD: "auth-guard" as const,
    LOGGER: "logger" as const,
    METRICS_COLLECTOR: "metrics-collector" as const,

    // --- 並行処理・スケーラビリティ層 ---
    TASK_EXECUTOR: "task-executor" as const,
    BATCH_PROCESSOR: "batch-processor" as const,
    WORKER: "worker" as const,
    JOB_QUEUE_MANAGER: "job-queue-manager" as const,
    CONCURRENCY_MANAGER: "concurrency-manager" as const,
    RATE_LIMITER: "rate-limiter" as const,
    LOAD_BALANCER: "load-balancer" as const,

    // --- パフォーマンス最適化層 ---
    PERFORMANCE_MANAGER: "performance-manager" as const,
    CONNECTION_POOL: "connection-pool" as const,
    CIRCUIT_BREAKER: "circuit-breaker" as const,
    BULK_OPERATION: "bulk-operation" as const,

    // --- セキュリティ実行層 ---
    SECURITY_EXECUTOR: "security-executor" as const,
    ACCESS_CONTROLLER: "access-controller" as const,
    THREAT_DETECTOR: "threat-detector" as const,
    AUDIT_LOGGER: "audit-logger" as const,
    CRYPTO_OPERATION: "crypto-operation" as const,
    TOKEN_VALIDATOR: "token-validator" as const,
} as const;

/**
 * ErrorLayer型
 */
export type ErrorLayerComponent =
    (typeof ERROR_LAYERS)[keyof typeof ERROR_LAYERS];

/**
 * エラー発生箇所の構造化記述（監査・トレーサビリティ用）
 */
export interface ErrorLayer {
    readonly module: string; // "UserService", "PaymentGateway", "AuthModule"
    readonly component: ErrorLayerComponent;
}

/**
 * エラーレイヤー作成ヘルパー
 */
export const createErrorLayer = (
    module: string,
    component: ErrorLayerComponent,
): ErrorLayer => ({
    module,
    component,
});

/**
 * 監査ログ用文字列化
 */
export const formatErrorLayer = (layer: ErrorLayer): string =>
    `${layer.module}:${layer.component}`;
