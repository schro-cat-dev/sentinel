import { Logger } from '../index';
import { GlobalConfig } from '../configs/global';
import { DetailedConfig } from '../configs/detail';

async function main() {
  const gConfig: GlobalConfig = {
    projectName: 'Fintech-Core-2026',
    environment: 'development', // 修正：TS(2741) 対応
    serviceId: 'payment-gateway-01',
    persistence: {
      enabled: true,
      bufferDirectory: './.wal_buffer',
      flushIntervalMs: 100,
      maxWalSizeMb: 50,
    },
    security: {
      enableHashChain: true,
      signingKeyId: 'kms-master-key-01',
      encryptionAtRest: true,
    },
    concurrency: {
      workerCount: 4,
      maxQueueSize: 1000,
      overflowStrategy: 'BLOCK',
    },
  };

  const dConfig: DetailedConfig = {
    masking: {
      enabled: true,
      rules: [{ type: 'PII_TYPE', category: 'CREDIT_CARD' }],
      preserveFields: ['traceId'],
    },
    intelligence: {
      enabled: true,
      taskRepository: {
        provider: 'POSTGRES',
        connectionConfig: {
          host: 'localhost',
          port: 5432,
          dbName: 'audit_db',
          username: 'admin', // 修正：SQLTaskRepository の定義と一致
          password: 'secure-password', // インターフェース側に追加済み
        },
        cacheTtlMs: 60000,
      },
      ai: {
        preferredModel: 'gpt-4o',
        loopProtectionDepth: 3,
        defaultTemperature: 0.7,
        maxTokens: 2048,
      },
    },
    transports: [
      {
        type: 'CLOUDWATCH',
        logGroupName: '/aws/lambda/payment-gateway',
        region: 'ap-northeast-1',
        retryStrategy: 'EXPONENTIAL_BACKOFF',
      },
    ],
  };

  // 起動
  const logger = await Logger.initialize(gConfig, dConfig);

  // ログ投入
  await logger.ingest({
    type: 'BUSINESS-AUDIT',
    level: 3,
    message: 'User initiated payment transaction',
    input: 'Card number: 1234-5678-9012-3456',
    actorId: 'user_99a',
    boundary: 'PaymentController',
  });

  await logger.shutdown();
}

main().catch(console.error);
