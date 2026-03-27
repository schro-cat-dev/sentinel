import { TaskResult } from "../../types/task";

export interface IngestionResult {
    traceId: string;
    hashChainValid: boolean;
    tasksGenerated: TaskResult[];
    masked: boolean;
}
