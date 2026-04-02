import { TaskResult } from "../../types/task";
import { SystemEventName } from "../../types/event";

/** 脅威レスポンスサマリー（Server IngestResponse.threat_responses 由来） */
export interface ThreatResponseSummary {
    responseId: string;
    eventName: string;
    strategy: string;
    blocked: boolean;
    blockTarget: string;
    analyzed: boolean;
    riskLevel: string;
    notified: boolean;
}

export interface IngestionResult {
    traceId: string;
    hashChainValid: boolean;
    tasksGenerated: TaskResult[];
    masked: boolean;
    /** 検知されたイベント情報（検知なしの場合null） */
    detection: { eventName: SystemEventName; priority: "HIGH" | "MEDIUM" | "LOW" } | null;
    /** dual-mode transport失敗時のエラーメッセージ（成功時はundefined） */
    transportError?: string;
    /** Server脅威レスポンス（Phase 2-C）。integration.threatResponseEnabled=true 時のみ設定 */
    threatResponses?: ThreatResponseSummary[];
}
