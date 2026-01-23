/**
 * AI エージェントの実行状態
 */
export type AIAgentStatus =
  | 'pending'
  | 'success'
  | 'failed'
  | 'requires_approval';

/**
 * AI エージェントからの推論結果
 */
export interface AgentInferenceResult {
  thought: string; // AIの思考プロセス
  action: string; // AIが決定した具体的なアクション名
  observation?: string; // 実行後の観察結果
  confidence: number; // 0.0 - 1.0 の信頼度
  nextStep?: string; // 次にすべきことの提案
}

/**
 * プロバイダー（OpenAI, Anthropic等）の抽象化
 */
export interface AgentResponse {
  result: AgentInferenceResult;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  model: string;
}
