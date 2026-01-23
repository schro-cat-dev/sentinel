import { Log } from "./log";

/**
 * システム全体で検知可能なイベントの型定義マップ
 * 金融取引、セキュリティ、コンプライアンスの各ドメインを網羅
 */
export interface SystemEventMap {
    SECURITY_INTRUSION_DETECTED: {
        ip: string;
        severity: number;
        rawLog: Log;
    };
    COMPLIANCE_VIOLATION: {
        ruleId: string;
        documentId: string;
        userId: string;
    };
    SYSTEM_CRITICAL_FAILURE: {
        component: string;
        errorDetails: string;
    };
    AI_ACTION_REQUIRED: {
        reason: string;
        suggestedTask: string;
        context: unknown;
    };
}

export type SystemEventName = keyof SystemEventMap;

/**
 * 検知結果のインターフェース
 * ジェネリクス <K> により、eventName と payload の整合性を強制
 */
export interface DetectionResult<K extends SystemEventName> {
    eventName: K;
    payload: SystemEventMap[K];
    priority: "HIGH" | "MEDIUM" | "LOW";
}

/**
 * Worker Thread からメインスレッドへ送られるメッセージの型定義
 */
export type WorkerToMainMessage =
    | {
          type: "EVENT_DETECTED";
          payload: {
              detection: DetectionResult<SystemEventName>;
              originalLog: Log;
          };
      }
    | { type: "LOG_PROCESSED"; payload: Log }
    | {
          type: "ERROR";
          payload: { message: string; error: string; traceId?: string };
      };
