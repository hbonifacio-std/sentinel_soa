import type { LogEntry } from '@/types/logEntry';
import type { PaginatedResponse, PageInfo } from '@/types/api';
import type { AlertAction, Threat } from '@/types/threat';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asNumber(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return fallback;
}

function asString(value: unknown, fallback = ''): string {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : fallback;
  }
  return fallback;
}

function asIsoDate(value: unknown, fallback: string): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  return fallback;
}

function parsePageInfo(rawInfo: unknown, page: number, limit: number, count: number): PageInfo {
  const info = isRecord(rawInfo) ? rawInfo : {};
  const totalRecords = asNumber(info.total_records, count);
  const resolvedPage = asNumber(info.page, page);
  const resolvedLimit = asNumber(info.limit, limit);
  return {
    total_records: totalRecords,
    page: resolvedPage,
    limit: resolvedLimit,
    next_page: typeof info.next_page === 'string' ? info.next_page : null,
    prev_page: typeof info.prev_page === 'string' ? info.prev_page : null,
  };
}

function buildFallbackPageInfo(page: number, limit: number, count: number): PageInfo {
  const hasPrev = page > 1;
  const hasNext = count === limit;
  return {
    total_records: count,
    page,
    limit,
    next_page: hasNext ? `?page=${page + 1}&limit=${limit}` : null,
    prev_page: hasPrev ? `?page=${page - 1}&limit=${limit}` : null,
  };
}

export function parsePaginatedResponse<T>(
  payload: unknown,
  page: number,
  limit: number,
  mapRow: (row: unknown, index: number) => T,
): PaginatedResponse<T> {
  if (Array.isArray(payload)) {
    const results = payload.map(mapRow);
    return {
      info: buildFallbackPageInfo(page, limit, results.length),
      results,
    };
  }

  if (isRecord(payload) && Array.isArray(payload.results)) {
    const results = payload.results.map(mapRow);
    return {
      info: parsePageInfo(payload.info, page, limit, results.length),
      results,
    };
  }

  return {
    info: buildFallbackPageInfo(page, limit, 0),
    results: [],
  };
}

function normalizeActions(value: unknown): AlertAction[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => {
      if (typeof entry === 'string') {
        return {
          comment: entry.trim(),
          created_at_utc: new Date().toISOString(),
        } satisfies AlertAction;
      }

      if (!isRecord(entry)) {
        return null;
      }

      const comment = asString(entry.comment);
      const createdAt = asIsoDate(entry.created_at_utc ?? entry.timestamp, new Date().toISOString());
      if (!comment) {
        return null;
      }

      return {
        comment,
        created_at_utc: createdAt,
      } satisfies AlertAction;
    })
    .filter((entry): entry is AlertAction => Boolean(entry));
}

function normalizeThreatLevel(value: unknown): Threat['threat_level'] {
  const level = asString(value, 'LOW').toUpperCase();
  if (level === 'CRITICAL' || level === 'HIGH' || level === 'MEDIUM' || level === 'LOW') {
    return level;
  }
  return 'LOW';
}

function normalizeKillChain(value: unknown): Threat['kill_chain_phase'] {
  const phase = asString(value, 'Unknown');
  const legacyMap: Record<string, Threat['kill_chain_phase']> = {
    reconnaissance: 'Reconnaissance',
    weaponization: 'Weaponization',
    delivery: 'Delivery',
    exploitation: 'Exploitation',
    installation: 'Installation',
    'command-and-control': 'Command and Control',
    'actions-on-objectives': 'Actions on Objectives',
  };

  const mappedLegacy = legacyMap[phase.toLowerCase()];
  if (mappedLegacy) {
    return mappedLegacy;
  }

  if (
    phase === 'Reconnaissance' ||
    phase === 'Weaponization' ||
    phase === 'Delivery' ||
    phase === 'Exploitation' ||
    phase === 'Installation' ||
    phase === 'Command and Control' ||
    phase === 'Actions on Objectives' ||
    phase === 'Unknown'
  ) {
    return phase;
  }
  return 'Unknown';
}

function normalizeMethod(value: unknown): LogEntry['http_method'] {
  const method = asString(value, 'GET').toUpperCase();
  const allowed = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
  return (allowed.includes(method) ? method : 'GET') as LogEntry['http_method'];
}

export function mapTelemetryRow(rawRow: unknown, index: number): LogEntry {
  const row = isRecord(rawRow) ? rawRow : {};
  const http = isRecord(row.http) ? row.http : {};
  const network = isRecord(row.network) ? row.network : {};
  const nowIso = new Date().toISOString();
  const sourceId = asString(row.source_id, 'unknown');
  const path = asString(row.request_uri ?? row.uri ?? http.path, '/');
  const query = asString(http.query, '');
  const requestUri = query ? `${path}?${query}` : path;
  return {
    id: asString(row.id, `${sourceId}-${index}-${Date.now()}`),
    source_id: sourceId,
    source_ip: asString(row.source_ip, asString(network.client_ip ?? row.client_ip, 'N/A')),
    http_method: normalizeMethod(row.http_method ?? row.method ?? http.method),
    request_uri: requestUri,
    response_code: asNumber(row.response_code ?? row.status ?? http.status_code, 0),
    user_agent: asString(row.user_agent ?? http.user_agent, '') || null,
    timestamp: asIsoDate(row.timestamp ?? row.timestamp_utc ?? row.created_at_utc, nowIso),
    bytes_sent: row.bytes_sent == null
      ? http.response_size_bytes == null
        ? null
        : asNumber(http.response_size_bytes, 0)
      : asNumber(row.bytes_sent, 0),
    raw: row,
  };
}

export function mapReportRow(rawRow: unknown, index: number): Threat {
  const row = isRecord(rawRow) ? rawRow : {};
  const details = isRecord(row.details) ? row.details : undefined;
  const threatActor = isRecord(row.threat_actor) ? row.threat_actor : undefined;
  const fallbackDate = new Date().toISOString();
  const reviewed = Boolean(row.reviewed);
  const resolved = Boolean(row.resolved);
  const resolvedAt = row.resolved_at_utc;

  return {
    id: asString(row.id),
    source_id: asString(row.source_id, '') || undefined,
    source_ip: asString(row.source_ip, asString(threatActor?.ip_address, asString(details?.source_ip, 'N/A'))),
    threat_level: normalizeThreatLevel(row.threat_level),
    threat_score: asNumber(row.threat_score, 0),
    targeted_asset: asString(row.targeted_asset, '') || null,
    kill_chain_phase: normalizeKillChain(row.kill_chain_phase),
    mitre_tactic: asString(row.mitre_tactic, '') || null,
    mitre_tactic_id: asString(row.mitre_tactic_id, '') || null,
    mitre_technique: asString(row.mitre_technique, '') || null,
    mitre_technique_id: asString(row.mitre_technique_id, '') || null,
    mitre_sub_technique: asString(row.mitre_sub_technique, '') || null,
    mitre_sub_technique_id: asString(row.mitre_sub_technique_id, '') || null,
    indicators_found: Array.isArray(row.indicators_found)
      ? row.indicators_found.filter((item): item is string => typeof item === 'string')
      : undefined,
    reasoning_summary: asString(row.reasoning_summary, '') || undefined,
    recommendation: asString(row.recommendation, '') || undefined,
    suggested_mitigations: Array.isArray(row.suggested_mitigations)
      ? (row.suggested_mitigations as Threat['suggested_mitigations'])
      : undefined,
    created_at_utc: asIsoDate(row.created_at_utc, fallbackDate),
    reviewed,
    resolved,
    resolved_at_utc: resolvedAt == null ? null : asIsoDate(resolvedAt, fallbackDate),
    actions: normalizeActions(row.actions),
    status: resolved ? 'resolved' : reviewed ? 'reviewing' : 'pending',
    details,
  };
}

export function parseTelemetryPage(payload: unknown, page: number, limit: number): PaginatedResponse<LogEntry> {
  return parsePaginatedResponse(payload, page, limit, mapTelemetryRow);
}

export function parseReportsPage(payload: unknown, page: number, limit: number): PaginatedResponse<Threat> {
  return parsePaginatedResponse(payload, page, limit, mapReportRow);
}



