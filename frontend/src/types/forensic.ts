export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string; // ISO UTC
  metadata?: Record<string, unknown>;
}

export interface ForensicAnalyzeRequest {
  query: string;
  source_id?: string | null;
  model_id?: string | null;
  session_id?: string | null;
}

export interface ForensicChatSession {
  session_id?: string | null;
  client_id: string;
  created_at_utc: string;
  updated_at_utc: string;
  messages: ChatMessage[];
  is_active: boolean;
  highlighted: string[];
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
  results: ForensicChatSession[];
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

