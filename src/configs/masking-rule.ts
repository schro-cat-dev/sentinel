/**
 * マスキングルール定義
 */
export type MaskingRule =
    | {
          type: "REGEX";
          pattern: RegExp;
          replacement: string;
          description: string;
      }
    | {
          type: "KEY_MATCH";
          sensitiveKeys: string[];
          replacement?: string;
      }
    | {
          type: "PII_TYPE";
          category: "CREDIT_CARD" | "PHONE" | "EMAIL" | "GOVERNMENT_ID";
      };
