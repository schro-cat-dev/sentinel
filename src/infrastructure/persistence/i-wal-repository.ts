// あとでインターフェースdir分離。
export interface WalWriteInput {
    transactionId: string; // TXN-20260124-001
    dataSize: number; // バイト数
    cause?: string; // 'duplicate', 'disk_full', 'crypto_fail'
}

export interface WalRepository {
    write(input: WalWriteInput): Promise<void>;
    initialize(transactionId: string): Promise<void>;
}
