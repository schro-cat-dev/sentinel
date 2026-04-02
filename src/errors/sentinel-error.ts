/**
 * SentinelError — パイプライン内部エラーの構造化型 (O-4)
 *
 * プレーンな Error の代わりに使用し、layer/operation/cause を付与して
 * ErrorRouter やロガーが構造化情報にアクセスできるようにする。
 */
export class SentinelError extends Error {
    public readonly layer: string;
    public readonly operation: string;
    public readonly cause?: Error;

    constructor(layer: string, operation: string, message: string, cause?: Error) {
        super(message);
        this.name = "SentinelError";
        this.layer = layer;
        this.operation = operation;
        this.cause = cause;
    }
}
