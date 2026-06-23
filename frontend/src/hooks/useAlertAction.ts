import { apiFetch } from '@/lib/apiClient';
import type { ActionPayload, AlertWorkflowResponse } from '@/types/api';

export function useAlertAction() {
  async function markAsReviewed(reportId: string) {
    return apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/review`, {
      method: 'PATCH',
    });
  }

  async function addAction(reportId: string, comment: string) {
    const payload: ActionPayload = { comment };
    return apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async function resolveReport(reportId: string) {
    return apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/resolve`, {
      method: 'PATCH',
    });
  }

  return { markAsReviewed, addAction, resolveReport };
}
