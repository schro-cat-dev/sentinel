/**
 * エラーペイロードプロトコル（SDK内部ユーティリティ用）
 * パイプライン本体では未使用。error-utils.ts の型定義として保持。
 */
export interface ErrorMeta {
    readonly operation?: string;
    readonly entityId?: string;
    readonly entityType?: string;
    readonly layer?: string;
    readonly httpStatus?: number;
    readonly traceId?: string;
    readonly context?: Record<string, string | number | boolean | null> | null;
}

export interface ErrorPayloadProtocol {
    readonly kind: string;
    readonly detailKind: string;
    readonly code: string;
    readonly message: string;
    readonly meta: ErrorMeta;
}
