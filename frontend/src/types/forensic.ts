export interface ForensicAnalyzeRequest {
  query: string;
  source_id?: string | null;
  page?: number;
  limit?: number;
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

