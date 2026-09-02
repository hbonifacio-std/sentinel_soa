import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '@/lib/apiClient';
import { sourceKeys } from '@/lib/queryKeys';
import { useSentinelStore } from '@/store/sentinelStore';

export function useSourceIds() {
  const sourceIds = useSentinelStore((state) => state.sourceIds);
  const activeSourceId = useSentinelStore((state) => state.activeSourceId);
  const setSourceIds = useSentinelStore((state) => state.setSourceIds);
  const setActiveSourceId = useSentinelStore((state) => state.setActiveSourceId);

  const query = useQuery({
    queryKey: sourceKeys.list(),
    queryFn: async () => apiFetch<string[]>('/api/v1/analytics/source_ids'),
    staleTime: 60_000,
  });

  useEffect(() => {
    if (!query.data) {
      return;
    }

    setSourceIds(query.data);
    if (!activeSourceId && query.data.length > 0) {
      setActiveSourceId(query.data[0]);
      return;
    }

    if (activeSourceId && !query.data.includes(activeSourceId)) {
      setActiveSourceId(query.data[0] ?? null);
    }
  }, [activeSourceId, query.data, setActiveSourceId, setSourceIds]);

  return {
    sourceIds,
    activeSourceId,
    loadingSources: query.isLoading || query.isFetching,
    error: query.error instanceof Error ? query.error.message : null,
  };
}

