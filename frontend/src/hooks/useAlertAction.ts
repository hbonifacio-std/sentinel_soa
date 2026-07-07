import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/apiClient';
import { statsKeys, threatKeys } from '@/lib/queryKeys';
import type { ActionPayload, AlertWorkflowResponse } from '@/types/api';

export function useAlertAction(sourceId: string | null) {
  const queryClient = useQueryClient();

  const reviewMutation = useMutation({
    mutationFn: async (reportId: string) => apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/review`, {
      method: 'PATCH',
    }),
  });

  const actionMutation = useMutation({
    mutationFn: async ({ reportId, comment }: { reportId: string; comment: string }) => {
      const payload: ActionPayload = { comment };
      return apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload),
      });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: async (reportId: string) => apiFetch<AlertWorkflowResponse>(`/api/v1/analytics/reports/${reportId}/resolve`, {
      method: 'PATCH',
    }),
  });

  async function invalidateRelatedQueries(): Promise<void> {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: threatKeys.lists() }),
      queryClient.invalidateQueries({ queryKey: statsKeys.detail(sourceId) }),
    ]);
  }

  async function markAsReviewed(reportId: string): Promise<AlertWorkflowResponse> {
    const result = await reviewMutation.mutateAsync(reportId);
    await invalidateRelatedQueries();
    return result;
  }

  async function addAction(reportId: string, comment: string): Promise<AlertWorkflowResponse> {
    const result = await actionMutation.mutateAsync({ reportId, comment });
    await invalidateRelatedQueries();
    return result;
  }

  async function resolveReport(reportId: string): Promise<AlertWorkflowResponse> {
    const result = await resolveMutation.mutateAsync(reportId);
    await invalidateRelatedQueries();
    return result;
  }

  return { markAsReviewed, addAction, resolveReport };
}
