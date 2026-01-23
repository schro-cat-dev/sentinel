import { TaskDefinition } from '../../types/task';

export interface ITaskRepository {
  /**
   * イベント名に基づき、動的にタスクの実行レシピを取得
   * 金融機関の独自DBや、国家プロジェクトの秘匿Configサーバ等
   */
  getTasksByEvent(eventName: string): Promise<TaskDefinition[]>;
}
