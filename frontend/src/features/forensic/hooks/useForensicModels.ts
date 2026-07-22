import { useQuery } from '@tanstack/react-query';
import { getAvailableModelsForChat } from '@/features/forensic/services/forensicApi';
import { forensicKeys } from '@/lib/queryKeys';

export function useForensicModels() {
  return useQuery({
    queryKey: forensicKeys.models(),
    queryFn: getAvailableModelsForChat,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}
