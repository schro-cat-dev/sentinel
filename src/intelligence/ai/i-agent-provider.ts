import { AgentResponse } from "../../types/agent";
import { TaskDefinition } from "../../types/task";
import { Log } from "../../types/log";

export interface IAgentProvider {
    execute(task: TaskDefinition, context: Log): Promise<AgentResponse>;
}
