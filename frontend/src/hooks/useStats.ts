import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { startOfHour } from 'date-fns';
import { mockStats } from '@/data/mockStats';
import { apiFetch } from '@/lib/apiClient';
import { statsKeys } from '@/lib/queryKeys';
import type { LogEntry } from '@/types/logEntry';
import type { MitreTacticRow, StatsResponse, ThreatLevelRow, TimelineRow } from '@/types/api';
import type {KillChainPhase, Threat} from '@/types/threat';
import {KillChainPhaseRow} from "@/features/dashboard/KillChainPhasePie";

const useMockData = String(import.meta.env.VITE_MOCK_DATA ?? 'false').toLowerCase() === 'true';

const threatLevelOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

function getBucketKey(value: string | undefined | null) {
  if (!value) {
    return null;
  }

  const parsedDate = new Date(value);
  if (Number.isNaN(parsedDate.getTime())) {
    return null;
  }

  return startOfHour(parsedDate).toISOString();
}

function getTopKey<T extends string | number>(counts: Map<T, number>) {
  let winner: T | null = null;
  let winnerCount = -1;

  counts.forEach((count, key) => {
    if (count > winnerCount) {
      winner = key;
      winnerCount = count;
    }
  });

  return winner;
}

function getRequestPath(threat: Threat, log?: LogEntry) {
  if (log?.request_uri) {
    return log.request_uri;
  }

  const detailsRecord: Record<string, unknown> | undefined = threat.details ?? undefined;
  const detailsRequestUri = detailsRecord?.request_uri;
  if (typeof detailsRequestUri === 'string' && detailsRequestUri.trim().length > 0) {
    return detailsRequestUri;
  }

  const rawTelemetry = (threat as Threat & { raw_telemetry?: Record<string, unknown> }).raw_telemetry;
  if (typeof rawTelemetry?.request_uri === 'string' && rawTelemetry.request_uri.trim().length > 0) {
    return rawTelemetry.request_uri;
  }

  return null;
}

export function useStats(sourceId: string | null, threats: Threat[], logs: LogEntry[]) {
  const statsQuery = useQuery({
    queryKey: statsKeys.detail(sourceId),
    enabled: Boolean(sourceId),
    queryFn: async () => {
      if (useMockData) {
        return mockStats;
      }

      const query = new URLSearchParams({ source_id: sourceId as string }).toString();
      return apiFetch<StatsResponse>(`/api/v1/analytics/stats?${query}`);
    },
  });

  const stats = statsQuery.data ?? null;

  const logsByBucket = useMemo(() => {
    const map = new Map<string, LogEntry[]>();
    logs.forEach((log) => {
      const key = getBucketKey(log.timestamp);
      if (!key) {
        return;
      }
      const rows = map.get(key) ?? [];
      rows.push(log);
      map.set(key, rows);
    });
    return map;
  }, [logs]);

  const logsByThreatId = useMemo(() => {
    return new Map(logs.map((log) => [log.id, log] as const));
  }, [logs]);

  const timelineData = useMemo((): TimelineRow[] => {
    const bucket = new Map<
      string,
      {
        timestamp: string;
        count: number;
        criticalCount: number;
        ipCounts: Map<string, number>;
      }
    >();

    threats.forEach((report) => {
      const key = getBucketKey(report.created_at_utc ?? report.details?.created_at_utc);
      if (!key) {
        return;
      }

      const existing = bucket.get(key) ?? { timestamp: key, count: 0, criticalCount: 0, ipCounts: new Map<string, number>() };
      existing.count += 1;

      if (report.source_ip) {
        existing.ipCounts.set(report.source_ip, (existing.ipCounts.get(report.source_ip) ?? 0) + 1);
      }

      if (report.threat_level === 'CRITICAL') {
        existing.criticalCount += 1;
      }

      bucket.set(key, existing);
    });

    return Array.from(bucket.values())
      .map((entry) => {
        const dominantIp = getTopKey(entry.ipCounts);
        const relatedLogs = (logsByBucket.get(entry.timestamp) ?? []).filter((log) => log.source_ip === dominantIp);
        const userAgentCounts = new Map<string, number>();
        const responseCodeCounts = new Map<number, number>();

        relatedLogs.forEach((log) => {
          if (log.user_agent) {
            userAgentCounts.set(log.user_agent, (userAgentCounts.get(log.user_agent) ?? 0) + 1);
          }
          if (Number.isFinite(log.response_code)) {
            responseCodeCounts.set(log.response_code, (responseCodeCounts.get(log.response_code) ?? 0) + 1);
          }
        });

        return {
          timestamp: entry.timestamp,
          count: entry.count,
          criticalCount: entry.criticalCount,
          dominantIp,
          dominantUserAgent: getTopKey(userAgentCounts),
          dominantResponseCode: getTopKey(responseCodeCounts),
        };
      })
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }, [logsByBucket, threats]);

  const mitreTactics = useMemo((): MitreTacticRow[] => {
    if (!useMockData && stats?.mitre_tactics?.length) {
      return stats.mitre_tactics.map((row) => ({
        _id: row._id,
        tacticId: undefined,
        count: row.count,
        techniques: [],
        topPaths: [],
      }));
    }

    const counts = new Map<
      string,
      {
        count: number;
        tacticId?: string;
        techniques: Map<string, { name: string; id: string }>;
        pathCounts: Map<string, number>;
      }
    >();

    threats.forEach((threat) => {
      const tactic = threat.mitre_tactic ?? threat.details?.mitre_tactic ?? 'UNKNOWN';
      const entry = counts.get(tactic) ?? {
        count: 0,
        tacticId: undefined,
        techniques: new Map<string, { name: string; id: string }>(),
        pathCounts: new Map<string, number>(),
      };

      entry.count += 1;

      entry.tacticId ??= threat.mitre_tactic_id ?? threat.details?.mitre_tactic_id ?? undefined;

      const techniqueName = threat.mitre_technique ?? threat.details?.mitre_technique ?? null;
      const techniqueId = threat.mitre_technique_id ?? threat.details?.mitre_technique_id ?? null;
      if (techniqueName && techniqueId && !entry.techniques.has(techniqueId)) {
        entry.techniques.set(techniqueId, { name: techniqueName, id: techniqueId });
      }

      const path = getRequestPath(threat, logsByThreatId.get(threat.id));
      if (path) {
        entry.pathCounts.set(path, (entry.pathCounts.get(path) ?? 0) + 1);
      }

      counts.set(tactic, entry);
    });

    return Array.from(counts.entries())
      .map(([key, value]) => ({
        _id: key,
        tacticId: value.tacticId,
        count: value.count,
        techniques: Array.from(value.techniques.values()),
        topPaths: Array.from(value.pathCounts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([path]) => path),
      }))
      .sort((a, b) => b.count - a.count || a._id.localeCompare(b._id));
  }, [logsByThreatId, stats, threats]);

  const threatLevelData = useMemo((): ThreatLevelRow[] => {
    const map = new Map<string, { count: number; activeCount: number; mitigatedCount: number }>();

    threats.forEach((threat) => {
      const entry = map.get(threat.threat_level) ?? { count: 0, activeCount: 0, mitigatedCount: 0 };
      entry.count += 1;
      if (threat.resolved === false) {
        entry.activeCount += 1;
      }
      if (threat.resolved === true) {
        entry.mitigatedCount += 1;
      }
      map.set(threat.threat_level, entry);
    });


    return Array.from(map.entries())
      .map(([_id, value]) => ({ _id: _id as ThreatLevelRow['_id'], ...value }))
      .sort((a, b) => (threatLevelOrder[a._id] ?? Number.MAX_SAFE_INTEGER) - (threatLevelOrder[b._id] ?? Number.MAX_SAFE_INTEGER));
  }, [threats]);

  const killChainPhaseData = useMemo<KillChainPhaseRow[]>(() => {
  const map = new Map<KillChainPhase, { count: number; activeCount: number; mitigatedCount: number }>();

  threats.forEach((threat) => {

    let phase: KillChainPhase = threat.kill_chain_phase;

    // 3. Acumulamos los datos
    const entry = map.get(phase) ?? { count: 0, activeCount: 0, mitigatedCount: 0 };
    entry.count += 1;
    if (threat.resolved === false) {
      entry.activeCount += 1;
    }
    if (threat.resolved === true) {
      entry.mitigatedCount += 1;
    }
    map.set(phase, entry);
  });

  return Array.from(map.entries()).map(([_id, value]) => ({
    _id,
    ...value,
  }));
}, [threats]);

  return {
    stats,
    timelineData,
    mitreTactics,
    threatLevelData,
    killChainPhaseData,
    loading: statsQuery.isLoading || statsQuery.isFetching,
    error: statsQuery.error instanceof Error ? statsQuery.error : null,
  };
}
