import { Log } from "./log";

/**
 * rawLogから安全に公開可能なフィールドのみ抽出したサブセット。
 * PII漏洩防止のため、input/details/actorId等はタスクハンドラに伝播させない。
 */
export interface SafeLogSubset {
    traceId: string;
    type: Log["type"];
    level: Log["level"];
    timestamp: string;
    boundary: string;
    serviceId: string;
    message: string;
    isCritical: boolean;
}

/**
 * システム全体で検知可能なイベントの型定義マップ
 * 金融取引、セキュリティ、コンプライアンスの各ドメインを網羅
 */
export interface SystemEventMap {
    SECURITY_INTRUSION_DETECTED: {
        ip: string;
        severity: number;
        rawLog: SafeLogSubset;
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
        context: Record<string, string | number | boolean | null> | null;
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
 * カスタム検知ルール定義。
 * 利用者がconfig経由で独自の検知ルールを追加可能にする。
 * conditions内の条件はAND結合。
 */
export interface DetectionRule {
    /** ルール一意識別子 */
    ruleId: string;
    /** マッチ時に生成されるイベント名 */
    eventName: SystemEventName;
    /** 検知結果の優先度 */
    priority: "HIGH" | "MEDIUM" | "LOW";
    /** 検知条件（全てAND結合） */
    conditions: DetectionRuleConditions;
}

export interface DetectionRuleConditions {
    /** ログタイプでフィルタ */
    logTypes?: string[];
    /** 最小レベル（以上） */
    minLevel?: number;
    /** 最大レベル（以下） */
    maxLevel?: number;
    /** メッセージの正規表現マッチ */
    messagePattern?: RegExp;
    /** タグのキー/値マッチ */
    tagMatch?: { key: string; value?: string };
    /** origin でフィルタ */
    origin?: string;
    /** isCritical フラグでフィルタ */
    isCritical?: boolean;
}
