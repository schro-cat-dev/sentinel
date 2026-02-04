export type OverflowStrategy = "BLOCK" | "FAIL_FAST" | "DROP_LOW_PRIORITY";

export interface RecoveryStatus {
    recoveredCount: number;
    truncated: boolean;
    errors?: Error[];
}

export interface IngestionResult {
    traceId: string;
    persisted: boolean;
    dispatched: boolean;
    overflowHandled?: boolean;
}
