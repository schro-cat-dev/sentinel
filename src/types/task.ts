/**
 * タスク実行アクションの定数定義
 * ランタイムでのバリデーションに使用するため 'as const' で定義
 */
export const TASK_ACTION_TYPES = [
  'AI_ANALYZE', // AIによる詳細解析
  'AUTOMATED_REMEDIATE', // 自動復旧・封じ込め
  'SYSTEM_NOTIFICATION', // 管理者への高度な通知
  'EXTERNAL_WEBHOOK', // 外部SIEMやSOCへの連携
] as const;

/**
 * タスク実行アクションの型
 */
export type TaskActionType = (typeof TASK_ACTION_TYPES)[number];

/**
 * 任務の優先度 (1: 最優先/即時 - 5: 低優先/バッチ)
 */
export type TaskPriority = 1 | 2 | 3 | 4 | 5;

export interface RetryStrategy {
  maxAttempts: number;
  initialIntervalMs: number;
  backoffFactor: number; // 指数バックオフ用
}

export interface TaskDefinition {
  taskId: string;
  eventName: string; // トリガーとなるイベント名 (e.g., "SECURITY_INTRUSION_DETECTED")
  actionType: TaskActionType;
  priority: 1 | 2 | 3 | 4 | 5; // 1が最高優先

  /**
   * 実行パラメータ
   * actionTypeに応じて、AIプロンプト、実行スクリプト、Webhook URLなどが格納される
   */
  executionParams: {
    promptTemplate?: string; // AI_ANALYZE用
    targetEndpoint?: string; // EXTERNAL_WEBHOOK用
    scriptIdentifier?: string; // AUTOMATED_REMEDIATE用
    payloadSchema?: Record<string, unknown>;
  };

  /**
   * ガードレール設定
   */
  guardrails: {
    requireHumanApproval: boolean; // 自動実行前に人間の承認を待つか
    timeoutMs: number;
    retryStrategy: RetryStrategy;
  };

  /**
   * AIループ防止タグ / 管理メタデータ
   */
  metadata: {
    originator: 'SYSTEM' | 'AI_AGENT';
    version: string;
  };
}
