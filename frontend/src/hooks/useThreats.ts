import { useCallback, useEffect, useMemo, useState } from 'react';
import { mockThreats } from '@/data/mockThreats';
import { apiFetch } from '@/lib/apiClient';
import { parseReportsPage } from '@/lib/analyticsParsers';
import type { PageInfo } from '@/types/api';
import type { AlertStatus, Threat } from '@/types/threat';

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

export function useThreats(sourceId: string | null, options: UseThreatsOptions = {}) {
  const page = options.page ?? 1;
  const limit = options.limit ?? 10;
  const [threats, setThreats] = useState<Threat[]>([]);
  const [pageInfo, setPageInfo] = useState<PageInfo>(defaultPageInfo);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchThreats = useCallback(async () => {
    if (!sourceId) {
      setThreats([]);
      setPageInfo({ ...defaultPageInfo, page, limit });
      return;
    }

    if (useMockData) {
      const filtered = mockThreats.filter((threat) => !sourceId || threat.source_id === sourceId);
      const start = (page - 1) * limit;
      const rows = filtered.slice(start, start + limit);
      setThreats(rows);
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
      const query = new URLSearchParams({
        source_id: sourceId,
        page: String(page),
        limit: String(limit),
      }).toString();
      const payload = await apiFetch<unknown>(`/api/v1/analytics/reports?${query}`);
      const parsed = parseReportsPage(payload, page, limit);
      setThreats(parsed.results);
      setPageInfo(parsed.info);
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }, [limit, page, sourceId]);

  useEffect(() => {
    void fetchThreats();

    if (!enablePolling || pollingMs <= 0) {
      return;
    }

    const interval = setInterval(() => {
      if (document.visibilityState === 'visible') {
        void fetchThreats();
      }
    }, pollingMs);

    return () => clearInterval(interval);
  }, [fetchThreats]);

  const mergedThreats = useMemo(
    () =>
      threats.map((threat) => ({
        ...threat,
        reviewed: Boolean(threat.reviewed),
        resolved: Boolean(threat.resolved),
        actions: threat.actions ?? [],
        status: (threat.resolved ? 'resolved' : threat.reviewed ? 'reviewing' : 'pending') as AlertStatus,
      })),
    [threats],
  );

  return { threats: mergedThreats, pageInfo, loading, error, refetch: fetchThreats };
}
