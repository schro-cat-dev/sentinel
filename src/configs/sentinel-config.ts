import { MaskingRule } from "./masking-rule";
import { Log } from "../types/log";
import { TaskRule, GeneratedTask, TaskResult } from "../types/task";
import { DetectionRule } from "../types/event";
import type { ErrorRoutingConfig } from "../error-routing/types";
import type { ValidationLimits } from "../validation/log-validator";

/**
 * SDKの内部ログ出力先。利用者が注入することでconsole.warn等を制御可能。
 * 未指定時はproduction環境で抑制、それ以外でconsole出力。
 */
export interface SentinelLogger {
    warn(message: string, context?: Record<string, string | number | boolean>): void;
    error(message: string, context?: Record<string, string | number | boolean>): void;
}

/**
 * 軽量メトリクスフック。
 * 全フィールドoptional。未設定のフックはゼロオーバーヘッド。
 * 各フック内の例外はパイプラインに影響しない（emitSafeで保護）。
 */
export interface SentinelMetrics {
    /** ログ取込み完了時 */
    onIngest?: () => void;
    /** イベント検知時（検知結果を引数で受取） */
    onDetection?: (detection: { eventName: string; priority: string }) => void;
    /** タスクディスパッチ完了時（結果を引数で受取） */
    onTaskDispatch?: (result: TaskResult) => void;
}

/**
 * 軽量トレーシングフック。
 * 分散トレーシングの統合ポイント。未設定時はゼロオーバーヘッド。
 * ユーザーが自身のOpenTelemetry等のインスタンスを接続する形で使用。
 */
export interface SentinelTracer {
    /** パイプライン処理開始時（spanの開始点） */
    onPipelineStart?: (context: { traceId: string; operation: string }) => void;
    /** パイプライン処理完了時（spanの終了点） */
    onPipelineEnd?: (context: { traceId: string; operation: string; durationMs: number; success: boolean }) => void;
}

/**
 * Sentinel SDK unified configuration
 */
export interface SentinelConfig {
    /** プロジェクト名 */
    projectName: string;

    /** サービス識別子（分散トレーシング用） */
    serviceId: string;

    /** 実行環境 */
    environment: "production" | "staging" | "development" | "local" | "test";

    /** PII マスキング設定 */
    masking: {
        enabled: boolean;
        rules: MaskingRule[];
        preserveFields: string[];
    };

    /** セキュリティ設定 */
    security: {
        enableHashChain: boolean;
        signingKeyId?: string;
    };

    /** カスタム検知ルール（組込みルールの後に評価される） */
    detectionRules?: DetectionRule[];

    /** タスク生成ルール（CORE VALUE） */
    taskRules: TaskRule[];

    /** イベントハンドラ */
    onLogProcessed?: (log: Log) => void;
    onTaskGenerated?: (task: GeneratedTask) => void;
    onTaskDispatched?: (result: TaskResult) => void;

    /** エラーハンドラ（パイプライン内部のswallowされるエラーを通知） */
    onError?: (error: Error, context: string) => void;

    /** SDK内部ログ出力先（省略時は環境に応じたデフォルト） */
    logger?: SentinelLogger;

    /** エラールーティング設定（省略時: 無効、既存emitSafe動作維持） */
    errorRouting?: ErrorRoutingConfig;

    /** バリデーション制限値のオーバーライド（省略時はDEFAULT_VALIDATION_LIMITS） */
    validationLimits?: Partial<ValidationLimits>;

    /**
     * メトリクスフック（省略時: ゼロオーバーヘッド）
     * 各フックは optional。必要なものだけ設定可能。
     */
    metrics?: SentinelMetrics;

    /**
     * トレーシングフック（省略時: ゼロオーバーヘッド）
     * OpenTelemetry等の分散トレーシングとの統合ポイント。
     */
    tracer?: SentinelTracer;

    /**
     * ホワイトリスト検証設定
     *
     * level で堅牢性 vs 柔軟性のトレードオフを制御する:
     * - "strict":   全ドメイン検証、拡張値の追加不可、不正値はエラー
     * - "standard": 全ドメイン検証、拡張値で追加可能、不正値はエラー（デフォルト）
     * - "permissive": 全ドメイン検証、不正値は警告のみ（エラーにしない）
     * - "off":      検証なし（開発・デバッグ用、本番非推奨）
     */
    whitelist?: {
        /** セキュリティレベル（省略時: "standard"） */
        level?: "strict" | "standard" | "permissive" | "off";
        /** 有効にするドメイン（省略時: 全て有効。levelが"off"の場合は無視） */
        enabledDomains?: ("security" | "task" | "privacy")[];
        /** フィールドごとの追加有効値（levelが"strict"の場合は無視） */
        extensions?: Partial<Record<string, string[]>>;
    };
}

/**
 * デフォルト設定
 */
export const createDefaultConfig = (
    overrides: Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">,
): SentinelConfig => {
    const defaults = {
        environment: "development" as const,
        masking: { enabled: false, rules: [] as MaskingRule[], preserveFields: ["traceId", "spanId"] },
        security: { enableHashChain: true },
        taskRules: [] as TaskRule[],
    };

    return {
        ...defaults,
        ...overrides,
        // Deep-merge nested objects to prevent silent security feature override (NEW-09)
        masking: {
            ...defaults.masking,
            ...overrides.masking,
        },
        security: {
            ...defaults.security,
            ...overrides.security,
        },
        // Deep-merge whitelist to prevent silent level/extensions override
        ...(overrides.whitelist ? {
            whitelist: {
                ...overrides.whitelist,
            },
        } : {}),
    };
};
