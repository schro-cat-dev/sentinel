import { Log } from "../types/log";

/**
 * 送信アダプターが実装すべき共通インターフェース
 */
export interface ILogTransport {
    readonly name: string;
    /**
     * ログを送信キューに追加する
     */
    send(log: Log): Promise<void>;
    /**
     * 終了時にバッファをフラッシュする
     */
    flush(): Promise<void>;
}
