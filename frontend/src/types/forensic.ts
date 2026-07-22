export interface ForensicAnalyzeRequest {
  query: string;
  source_id?: string | null;
  page?: number;
  limit?: number;
  model_id?: string | null;
}

export interface ForensicAnalysisRecord {
  analysis_id: string;
  query: string;
  source_id?: string | null;
  created_at_utc: string;
  total_matches: number;
  highlights: string[];
  markdown_report: string;
  sample_results: Array<Record<string, unknown>>;
  llm_provider_used?: string | null;
  llm_model_used?: string | null;
  provider_source?: string | null;
}

export interface ForensicHistoryInfo {
  total_records: number;
  page: number;
  limit: number;
  next_page: string | null;
  prev_page: string | null;
}

export interface ForensicHistoryResponse {
  info: ForensicHistoryInfo;
  results: ForensicAnalysisRecord[];
}

export interface AvailableModelDef {
  provider: string;
  model_name: string;
  max_output_tokens?: number | null;
  max_input_tokens?: number | null;
}

export interface AvailableModelsResponse {
  default_model_id: string | null;
  available_models: Record<string, AvailableModelDef>;
}

