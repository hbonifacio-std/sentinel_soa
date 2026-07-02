import { useCallback, useEffect, useState } from 'react';
import { apiFetch } from '@/lib/apiClient';
import { parseTelemetryPage } from '@/lib/analyticsParsers';
import { mockLogs } from '@/data/mockLogs';
import type { PageInfo } from '@/types/api';
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
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [pageInfo, setPageInfo] = useState<PageInfo>(defaultPageInfo);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchLogs = useCallback(async () => {
    if (useMockData) {
      const filtered = mockLogs.filter((log) => !sourceId || log.source_id === sourceId);
      const start = (page - 1) * limit;
      const rows = filtered.slice(start, start + limit);
      setLogs(rows);
      setPageInfo({
        total_records: filtered.length,
        page,
        limit,
        next_page: start + limit < filtered.length ? `?page=${page + 1}&limit=${limit}` : null,
        prev_page: page > 1 ? `?page=${page - 1}&limit=${limit}` : null,
      });
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const query = new URLSearchParams({ source_id: String(sourceId) , page: String(page), limit: String(limit) }).toString();
      const payload = await apiFetch<unknown>(`/api/v1/analytics/logs_row_telemetry?${query}`);
      const parsed = parseTelemetryPage(payload, page, limit);
      const filteredRows = parsed.results.filter((log) => !sourceId || log.source_id === sourceId);
      setLogs(filteredRows);
      setPageInfo(parsed.info);
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }, [limit, page, sourceId]);

  useEffect(() => {
    void fetchLogs();
  }, [fetchLogs]);

  return { logs, pageInfo, loading, error, refetch: fetchLogs };
}
