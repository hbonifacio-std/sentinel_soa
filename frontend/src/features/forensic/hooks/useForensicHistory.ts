import { useQuery } from '@tanstack/react-query';
import { forensicKeys } from '@/lib/queryKeys';
import { getForensicHistory, getForensicReport } from '@/features/forensic/services/forensicApi';

export function useForensicHistory(sourceId: string | null, page: number, limit: number) {
  return useQuery({
    queryKey: forensicKeys.history(sourceId, page, limit),
    queryFn: async () => getForensicHistory(sourceId, page, limit),
  });
}

export function useForensicReport(analysisId: string | null) {
  return useQuery({
    queryKey: forensicKeys.report(analysisId ?? 'none'),
    queryFn: async () => getForensicReport(analysisId ?? ''),
    enabled: Boolean(analysisId),
  });
}

