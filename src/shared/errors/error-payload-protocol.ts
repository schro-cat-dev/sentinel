import { ErrorLayer } from "../constants";
import { ErrorKind } from "../constants/error-protocol-kind";
import { HttpStatusCode } from "../constants/http-status";
import { DetailErrorKind } from "../constants/kinds";

export interface ErrorMeta {
    readonly operation?: string; // TODO di堅牢化（ホワイトリスト管理）
    readonly entityId?: string; //  問題のある1レコードを特定→再現/調査/監査、取引ID（コンプラ）
    readonly entityType?: string;
    readonly layer?: ErrorLayer; // スタックトレース補完、責任範囲特定、監査証跡（どのレイヤで失敗か）→ 詳細情報追加考える。Application層はControllerで一括で扱う。
    readonly httpStatus?: HttpStatusCode;
    readonly traceId?: string;
    // readonly filePath?: string; // 外部にデータの場所漏洩。カプセル化するので。あとで変なミスしないよう参考に残す。
    readonly context?: Record<string, string | number | boolean | null> | null; // null: 未特定、不在。PII情報はマスクするか専用の内部変換または情報送受信ガード層を採用。（柔軟性トレードオフ）
}

export interface ErrorPayloadProtocol {
    readonly kind: ErrorKind;
    readonly detailKind: DetailErrorKind;
    readonly code: string;
    readonly message: string;
    readonly meta: ErrorMeta;
}
