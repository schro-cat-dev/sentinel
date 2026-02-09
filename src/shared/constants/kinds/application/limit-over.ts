// 全て "LimitOver" で統一 → 集計・監視容易
export const LIMIT_OVER_ERROR_KINDS = {
    API_LIMIT: "ApiLimitOver" as const,
    DATA_SIZE: "DataSizeLimitOver" as const,
    CONCURRENCY: "ConcurrencyLimitOver" as const,
} as const;

export type LimitOverKind =
    (typeof LIMIT_OVER_ERROR_KINDS)[keyof typeof LIMIT_OVER_ERROR_KINDS];
