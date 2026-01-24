// ないとは思うものの、久しぶりのリハビリなのでひとことメモ。
// 具体は抽象に依存。あとはそのレベルかんと範囲（共通化による拡張時の影響範囲、処理や管理複雑さのトレードオフのでの方針選定）気をつけること。

export interface AppErrorMeta {
    readonly operation?: string; // TODO di堅牢化
    readonly entityId?: string; //  問題のある1レコードを特定→再現/調査/監査、取引ID（コンプラ）
    readonly entityType?: string;
    readonly layer?: "Controller" | "Service" | "Repository" | "External"; // スタックトレース補完、責任範囲特定、監査証跡（どのレイヤで失敗か）→ 詳細情報追加考える。Application層はControllerで一括で扱う。
    readonly httpStatus?: number; // TODO 堅牢化、他個人libからとってくる
    readonly traceId?: string;
    // readonly filePath?: string; // 外部にデータの場所漏洩。カプセル化するので。あとで変なミスしないよう参考に残す。
    readonly context?: Record<string, string | number | boolean | null> | null; // null: 未特定、不在。PII情報はマスクするか専用の内部変換または情報送受信ガード層を採用。（柔軟性トレードオフ）
}

export type AppErrorKind =
    // 集合論的に見て重複より全てをカバーできているか。
    // 1. 粒度的にwalとかdbとかはexternalに分類。
    // 2. ServiceUnavailableは障害などをカバー。
    "External" | "BusinessConflict" | "ServiceUnavailable" | "Internal";

// TODO 現状ハードコード->ユニオンに。（db, wal, ...それぞれで統合してそれらを統合するようにするだけ。検索・比較コスト増えるなら方針修正。）
export type DetailErrorKind =
    | "Validation"
    | "Auth"
    | "Permission"
    | "NotFound"
    | "Conflict"
    | "RateLimit"
    | "Database"
    | "WalInit"
    | "WalWrite"
    | "WalRead"
    | "WalCrypto"
    | "WalDiskFull"
    | "DbConnection"
    | "DbQuery"
    | "DbTransaction"
    | "DbConstraint"
    | "DbTimeout"
    | "DbDeadlock"
    | "DbDuplicateKey";

export interface AppErrorBase {
    readonly kind: AppErrorKind;
    readonly detailKind: DetailErrorKind;
    readonly code: string;
    readonly message: string;
    readonly meta: AppErrorMeta;
}

// NOTE: 一旦、連携先のドメイン情報の片鱗が残っているので残す。別途個別ファイルとして定義実装の際に利用。
// export type ApplicationError =
//     | ValidationError
//     | AuthError
//     | WalError
//     | ExternalError;

// export interface ValidationError extends AppErrorBase {
//     readonly kind: "Validation";
//     readonly field?: string;
//     readonly value?: string | number | boolean;
// }

// export interface AuthError extends AppErrorBase {
//     readonly kind: "Auth";
//     readonly reason: "Expired" | "Invalid" | "InsufficientScope";
// }

// export interface WalError extends AppErrorBase {
//     readonly kind:
//         | "WalInit"
//         | "WalWrite"
//         | "WalRead"
//         | "WalCrypto"
//         | "WalDiskFull";
//     readonly operation:
//         | "append"
//         | "recover"
//         | "truncate"
//         | "rotate"
//         | "initialize";
//     readonly filePath?: string;
// }

// export interface ExternalError extends AppErrorBase {
//     readonly kind: "External";
//     readonly service: "payment" | "email" | "sms" | "notification";
//     readonly requestId?: string;
// }

// export const validationError = (
//     code: string,
//     message: string,
//     field?: string,
//     value?: string | number | boolean,
//     meta: AppErrorMeta = { httpStatus: 400 },
// ): ValidationError => ({
//     kind: "Validation",
//     code,
//     message,
//     meta,
//     field,
//     value,
// });

// export const authError = (
//     code: string,
//     message: string,
//     reason: AuthError["reason"],
//     meta: AppErrorMeta = { httpStatus: 401 },
// ): AuthError => ({
//     kind: "Auth",
//     code,
//     message,
//     meta,
//     reason,
// });
