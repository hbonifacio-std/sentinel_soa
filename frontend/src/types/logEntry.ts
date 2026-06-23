export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'HEAD'
  | 'OPTIONS'
  | 'PATCH';

export interface LogEntry {
  _id: string;
  source_id: string;
  source_ip: string;
  http_method: HttpMethod;
  request_uri: string;
  response_code: number;
  user_agent: string | null;
  timestamp: string;
  bytes_sent: number | null;
  raw?: Record<string, unknown>;
}

