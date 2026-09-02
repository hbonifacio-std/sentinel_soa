import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '@/lib/apiClient';
import { parseTelemetryPage } from '@/lib/analyticsParsers';
import { mockLogs } from '@/data/mockLogs';
import { logKeys } from '@/lib/queryKeys';
import type { PageInfo, PaginatedResponse } from '@/types/api';
import type { LogEntry } from '@/types/logEntry';

const useMockData = String(import.meta.env.VITE_MOCK_DATA ?? 'false').toLowerCase() === 'true';

interface UseLogsOptions {
  page?: number;
  limit?: number;
  sourceId?: string;
}

const defaultPageInfo: PageInfo = {
  total_records: 0,
  page: 1,
  limit: 25,
  next_page: null,
  prev_page: null,
};

export function useLogs(sourceId: string | null, options: UseLogsOptions = {}) {
  const page = options.page ?? 1;
  const limit = options.limit ?? 25;
  const query = useQuery({
    queryKey: logKeys.list(sourceId, page, limit),
    queryFn: async () => {
      if (useMockData) {
        const filtered = mockLogs.filter((log) => !sourceId || log.source_id === sourceId);
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

      const params = new URLSearchParams({ page: String(page), limit: String(limit) });
      if (sourceId) {
        params.set('source_id', sourceId);
      }

      const payload = await apiFetch<PaginatedResponse<LogEntry> | LogEntry[]>(`/api/v1/analytics/logs_row_telemetry?${params.toString()}`);
      const parsed = parseTelemetryPage(payload, page, limit);
      return {
        results: parsed.results.filter((log) => !sourceId || log.source_id === sourceId),
        info: parsed.info,
      };
    },
  });

  return {
    logs: query.data?.results ?? [],
    pageInfo: query.data?.info ?? { ...defaultPageInfo, page, limit },
    loading: query.isLoading || query.isFetching,
    error: query.error instanceof Error ? query.error : null,
  };
}
