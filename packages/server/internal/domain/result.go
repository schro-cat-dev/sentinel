package domain

// IngestionResult パイプライン処理結果
type IngestionResult struct {
	TraceID        string
	HashChainValid bool
	Masked         bool
	TasksGenerated []TaskResult
}
