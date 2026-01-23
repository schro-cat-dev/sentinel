export interface GlobalConfig {
  projectName: string;
  serviceId: string; // クラスター内での識別子。分散トレーシングに必須
  environment:
    | 'production'
    | 'staging'
    | 'sandbox'
    | 'audit_only'
    | 'development'
    | 'local';

  concurrency: {
    workerCount: number; // 処理を分散する Worker 数
    maxQueueSize: number; // メモリ上の限界値。これを超えると戦略が発動
    /**
     * BLOCK: 生成元を待機させる（確実性を優先）
     * DROP_LOW_PRIORITY: DEBUGレベルなどを捨ててシステム継続
     * FAIL_FAST: 即座にエラーを投げる
     */
    overflowStrategy: 'BLOCK' | 'DROP_LOW_PRIORITY' | 'FAIL_FAST';
  };

  persistence: {
    enabled: boolean;
    bufferDirectory: string; // クラッシュ復旧用の WAL (Write Ahead Log) 保存先
    flushIntervalMs: number; // どの程度の頻度で物理ディスクに書き込むか
    maxWalSizeMb: number; // 肥大化防止
  };

  security: {
    enableHashChain: boolean; // $H_n = \text{hash}(L_n, H_{n-1})$ による改ざん検知
    signingKeyId?: string; // ハッシュに対する電子署名（非改ざん証明）
    encryptionAtRest: boolean; // WALファイル自体の暗号化
  };
}

// export interface GlobalConfig {
//   projectName: string;
//   environment: 'production' | 'staging' | 'audit';
//   concurrency: {
//     workerCount: number; // 並列Worker数
//     highWaterMark: number; // キューの最大保持数
//   };
//   persistence: {
//     walPath: string; // クラッシュ防止用WALの保存先
//     retentionDays: number;
//   };
//   security: {
//     signatureAlgorithm: 'SHA-256' | 'ECDSA';
//     enableHashChain: boolean; // ハッシュチェーンの有効化
//   };
// }
