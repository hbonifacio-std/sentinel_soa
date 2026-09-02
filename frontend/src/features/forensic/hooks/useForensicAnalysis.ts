import { useMutation, useQueryClient } from '@tanstack/react-query';
import { analyzeForensicActivity } from '@/features/forensic/services/forensicApi';
import { forensicKeys } from '@/lib/queryKeys';
import type { ForensicAnalyzeRequest } from '@/types/forensic';

export function useForensicAnalysis(sourceId: string | null, page: number, limit: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (payload: ForensicAnalyzeRequest) => analyzeForensicActivity(payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: forensicKeys.history(sourceId, page, limit) });
    },
  });
}

