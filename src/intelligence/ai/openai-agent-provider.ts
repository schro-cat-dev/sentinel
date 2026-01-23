import { AgentResponse, AgentInferenceResult } from "../../types/agent";
import { TaskDefinition } from "../../types/task";
import { Log } from "../../types/log";
import { IAgentProvider } from "./i-agent-provider";

export class OpenAIAgentProvider implements IAgentProvider {
    constructor(
        private readonly apiKey: string,
        private readonly model: string,
    ) {
        if (!apiKey)
            throw new Error("API Key is required for OpenAIAgentProvider");
    }

    public async execute(
        task: TaskDefinition,
        context: Log,
    ): Promise<AgentResponse> {
        // 1. プロンプトの組み立て（Hydration）
        const prompt = this.hydratePrompt(
            task.executionParams.promptTemplate ?? "",
            context,
        );

        // 2. 実際の API 呼び出し (prompt を確実に利用)
        console.log(
            `[AgentProvider:${this.model}] Trace: ${context.traceId} | Payload: ${prompt.substring(0, 50)}...`,
        );

        // 本来はここで fetch 等を用いて OpenAI API を叩く
        // const response = await this.client.chat.completions.create({ messages: [{ role: 'user', content: prompt }] });

        const mockInference: AgentInferenceResult = {
            thought:
                "Detected high-frequency access from a single actorId. Cross-referencing with boundary data.",
            action: "ENFORCE_MFA",
            confidence: 0.98,
            observation: `Analysis completed for actor: ${context.actorId ?? "unknown"}`,
        };

        return {
            result: mockInference,
            usage: {
                promptTokens: 450,
                completionTokens: 120,
                totalTokens: 570,
            },
            model: this.model,
        };
    }

    /**
     * 型安全なプロンプト置換
     * any を排除し、Log 型のキーであることを保証してアクセスする
     */
    private hydratePrompt(template: string, context: Log): string {
        return template.replace(/{{(.*?)}}/g, (match, key: string) => {
            const trimmedKey = key.trim();

            // Log 型のプロパティ名であるかを確認する型ガード
            if (this.isValidLogKey(trimmedKey, context)) {
                const value = context[trimmedKey];

                if (value === undefined || value === null) return "N/A";

                // オブジェクト型（tags 等）の場合はシリアライズして埋め込む
                if (typeof value === "object") return JSON.stringify(value);

                return String(value);
            }

            return match; // 合致するキーがない場合はそのまま返す
        });
    }

    /**
     * 実行時型ガード: string が Log の有効なキーであることを保証する
     */
    private isValidLogKey(key: string, obj: Log): key is keyof Log {
        return key in obj;
    }
}
