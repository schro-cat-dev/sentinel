import { TaskResult } from "../../types/task";
import { SystemEventName } from "../../types/event";

export interface IngestionResult {
    traceId: string;
    hashChainValid: boolean;
    tasksGenerated: TaskResult[];
    masked: boolean;
    /** 検知されたイベント情報（検知なしの場合null） */
    detection: { eventName: SystemEventName; priority: "HIGH" | "MEDIUM" | "LOW" } | null;
}
