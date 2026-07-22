import { apiFetch } from '@/lib/apiClient';
import type {
  ForensicAnalyzeRequest,
  ForensicAnalysisRecord,
  ForensicHistoryResponse,
  AvailableModelsResponse,
} from '@/types/forensic';

export async function analyzeForensicActivity(payload: ForensicAnalyzeRequest): Promise<ForensicAnalysisRecord> {
  return apiFetch<ForensicAnalysisRecord>('/api/v1/forensic/analyze', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getForensicHistory(
  sourceId: string | null,
  page: number,
  limit: number,
): Promise<ForensicHistoryResponse> {
  const params = new URLSearchParams({ page: String(page), limit: String(limit) });
  if (sourceId) {
    params.set('source_id', sourceId);
  }

  return apiFetch<ForensicHistoryResponse>(`/api/v1/forensic/history?${params.toString()}`);
}

export async function getForensicReport(analysisId: string): Promise<ForensicAnalysisRecord> {
  return apiFetch<ForensicAnalysisRecord>(`/api/v1/forensic/history/${analysisId}`);
}

export async function getAvailableModelsForChat(): Promise<AvailableModelsResponse> {
  return apiFetch<AvailableModelsResponse>('/api/v1/forensic/models');
}

