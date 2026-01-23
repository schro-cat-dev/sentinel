import { Logger } from '../index';
// 設定は basic_usage.ts と同様と仮定

async function runAnomalyDemo() {
  const logger = Logger.getInstance();

  console.log('--- シナリオ開始: 不審なアクセスの検知 ---');

  // 1. 短時間に大量の失敗ログを想定
  // 内部の RuleBasedDetector が SECURITY_INTRUSION_DETECTED を発火させる
  for (let i = 0; i < 5; i++) {
    await logger.ingest({
      traceId: `intrusion-trace-${Date.now()}`,
      type: 'SECURITY',
      level: 5,
      message: 'Failed login attempt from untrusted IP',
      input: { ip: '192.168.10.55', user: 'admin_test' },
      boundary: 'AuthService',
      isCritical: true,
      triggerAgent: true, // AIの起動を許可
    });
  }

  /**
   * ここで裏側では以下のフローが自動実行されます：
   * 1. WorkerPool 内で EventDetector が「短時間の失敗」を検知
   * 2. EVENT_DETECTED が TaskManager へ飛ぶ
   * 3. TaskManager が SQLTaskRepository から「分析タスク」を取得
   * 4. OpenAIAgentProvider が起動し、IPや過去ログを分析（Thought / Action）
   * 5. AIの思考ログ（agentBackLog付）が IngestionEngine に再投入される
   */

  console.log('--- AIが分析を開始しました（バックグラウンド） ---');

  // 処理完了を少し待機（デモ用）
  await new Promise((r) => setTimeout(r, 5000));

  await logger.shutdown();
}

runAnomalyDemo().catch((err) => {
  console.error('[Demo] Failed:', err);
});
