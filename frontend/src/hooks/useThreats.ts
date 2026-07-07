import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { mockThreats } from '@/data/mockThreats';
import { apiFetch } from '@/lib/apiClient';
import { parseReportsPage } from '@/lib/analyticsParsers';
import type { PageInfo, PaginatedResponse } from '@/types/api';
import { threatKeys } from '@/lib/queryKeys';
import type { Threat } from '@/types/threat';

const pollingMs = Number(import.meta.env.VITE_POLLING_INTERVAL_MS ?? 30000);
const useMockData = String(import.meta.env.VITE_MOCK_DATA ?? 'false').toLowerCase() === 'true';
const enablePolling = String(import.meta.env.VITE_ENABLE_POLLING ?? 'false').toLowerCase() === 'true';

interface UseThreatsOptions {
  page?: number;
  limit?: number;
}

const defaultPageInfo: PageInfo = {
  total_records: 0,
  page: 1,
  limit: 10,
  next_page: null,
  prev_page: null,
};

function normalizeThreatStatus(reviewed: boolean, resolved: boolean): Threat['status'] {
  if (resolved) {
    return 'resolved';
  }
  if (reviewed) {
    return 'reviewing';
  }
  return 'pending';
}

export function useThreats(sourceId: string | null, options: UseThreatsOptions = {}) {
  const page = options.page ?? 1;
  const limit = options.limit ?? 10;
  const query = useQuery({
    queryKey: threatKeys.list(sourceId, page, limit),
    queryFn: async () => {
      if (!sourceId) {
        return {
          results: [] as Threat[],
          info: { ...defaultPageInfo, page, limit },
        };
      }

      if (useMockData) {
        const filtered = mockThreats.filter((threat) => !sourceId || threat.source_id === sourceId);
        const start = (page - 1) * limit;
        const rows = filtered.slice(start, start + limit);
        return {
          results: rows,
          info: {
            total_records: filtered.length,
            page,
            limit,
            next_page: start + limit < filtered.length ? `?page=${page + 1}&limit=${limit}` : null,
            prev_page: page > 1 ? `?page=${page - 1}&limit=${limit}` : null,
          },
        };
      }

      const queryString = new URLSearchParams({
        source_id: sourceId,
        page: String(page),
        limit: String(limit),
      }).toString();
      const payload = await apiFetch<PaginatedResponse<Threat> | Threat[]>(`/api/v1/analytics/reports?${queryString}`);
      return parseReportsPage(payload, page, limit);
    },
    refetchInterval: enablePolling && pollingMs > 0 ? pollingMs : false,
  });

  const normalizedThreats = useMemo(
    () =>
      (query.data?.results ?? []).map((threat) => ({
        ...threat,
        reviewed: Boolean(threat.reviewed),
        resolved: Boolean(threat.resolved),
        actions: threat.actions ?? [],
        status: normalizeThreatStatus(Boolean(threat.reviewed), Boolean(threat.resolved)),
      })),
    [query.data?.results],
  );

  return {
    threats: normalizedThreats,
    pageInfo: query.data?.info ?? { ...defaultPageInfo, page, limit },
    loading: query.isLoading || query.isFetching,
    error: query.error instanceof Error ? query.error : null,
  };
}
