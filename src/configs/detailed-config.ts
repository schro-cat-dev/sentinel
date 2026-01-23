import { DBConnectionConfig } from "../intelligence/task/sql-task-repository";

/**
 * 高度な機密情報保護ルール
 */
export type MaskingRule =
    | {
          type: "REGEX";
          pattern: RegExp;
          replacement: string;
          description: string;
      }
    | { type: "KEY_MATCH"; sensitiveKeys: string[]; replacement: string }
    | {
          type: "PII_TYPE";
          category: "CREDIT_CARD" | "PHONE" | "EMAIL" | "GOVERNMENT_ID";
      };

/**
 * 送信先ごとの固有設定
 */
export type TransportDefinition =
    | {
          type: "CLOUDWATCH";
          logGroupName: string;
          region: string;
          batchSize?: number;
          retryStrategy: "EXPONENTIAL_BACKOFF" | "IMMEDIATE";
      }
    | {
          type: "POSTGRES";
          tableName: string;
          connectionString: string;
          schema: "AUDIT" | "SYSTEM";
      }
    | {
          type: "HTTP_WEBHOOK";
          endpoint: string;
          headers: Record<string, string>;
          timeoutMs: number;
      };

/**
 * タスクリポジトリの設定（判別共用体）
 * ここで provider と connectionConfig を 1対1 で結びつける
 */
export type TaskRepositoryConfig =
    | {
          provider: "POSTGRES";
          connectionConfig: DBConnectionConfig;
          cacheTtlMs: number;
      }
    | {
          provider: "DYNAMODB";
          connectionConfig: { tableName: string; region: string };
          cacheTtlMs: number;
      }
    | {
          provider: "REDIS";
          connectionConfig: { host: string; port: number; password?: string };
          cacheTtlMs: number;
      }
    | {
          provider: "REMOTE_API";
          connectionConfig: { endpoint: string; apiKey: string };
          cacheTtlMs: number;
      };

export interface DetailedConfig {
    masking: {
        enabled: boolean;
        rules: MaskingRule[];
        customAnonymizer?: (value: unknown) => string;
        preserveFields: string[]; // 監査に必要な traceId などを保護するホワイトリスト
    };

    intelligence: {
        enabled: boolean;
        taskRepository: TaskRepositoryConfig;
        ai: {
            preferredModel: "gpt-4o" | "claude-3-5-sonnet" | "custom-on-prem";
            loopProtectionDepth: number; // AIが生成したログから連鎖するタスクの最大深さ
            defaultTemperature: number;
            maxTokens: number;
        };
    };

    transports: TransportDefinition[]; // 送信先（CloudWatch, DB等）の配列
}

// /**
//  * 詳細設定の完成形
//  */
// export interface DetailedConfig {
//   masking: {
//     enabled: boolean;
//     rules: MaskingRule[];
//     /**
//      * カスタム匿名化ロジック
//      * unknown を受け取り、型安全に処理した上で文字列を返すことを強制
//      */
//     customAnonymizer?: (value: unknown) => string;
//   };
//   intelligence: {
//     // タスクリポジトリの接続設定（SQLだけでなくRedisやAPIも許容する拡張性）
//     taskRepository: {
//       provider: 'SQL' | 'API' | 'LOCAL_JSON';
//       config: Record<string, unknown>;
//     };
//     ai: {
//       enabled: boolean;
//       model: 'gpt-4o' | 'claude-3-5-sonnet' | 'custom-on-prem';
//       loopProtectionDepth: number;
//       temperature: number; // 0.0 - 1.0
//     };
//   };
//   transports: TransportDefinition[];
// }
