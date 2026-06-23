import { useEffect, useMemo, useState } from 'react';
import { Paginator } from '@/components/Paginator';
import { LogsFilters } from '@/features/logs/LogsFilters';
import { LogsTable } from '@/features/logs/LogsTable';
import { useLogs } from '@/hooks/useLogs';
import { useSentinelStore } from '@/store/sentinelStore';

export default function LogsPage() {
  const sourceId = useSentinelStore((state) => state.activeSourceId);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const { logs, pageInfo, loading, error } = useLogs(sourceId, { page, limit });
  const [search, setSearch] = useState('');
  const [method, setMethod] = useState('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    setPage(1);
  }, [sourceId]);

  const filtered = useMemo(() => {
    return logs.filter((log) => {
      if (method && log.http_method !== method) {
        return false;
      }
      if (status === '2xx' && (log.response_code < 200 || log.response_code >= 300)) {
        return false;
      }
      if (status === '4xx' && (log.response_code < 400 || log.response_code >= 500)) {
        return false;
      }
      if (status === '5xx' && (log.response_code < 500 || log.response_code >= 600)) {
        return false;
      }
      const q = search.trim().toLowerCase();
      if (!q) {
        return true;
      }
      return log.source_ip.toLowerCase().includes(q) || log.request_uri.toLowerCase().includes(q);
    });
  }, [logs, method, search, status]);

  return (
    <div className="space-y-4">
      <LogsFilters
        search={search}
        method={method}
        status={status}
        onSearch={setSearch}
        onMethod={setMethod}
        onStatus={setStatus}
        logs={logs}
      />
      {loading ? <p className="text-sm text-slate-400">Cargando logs...</p> : null}
      {error ? <p className="text-sm text-red-400">{error.message}</p> : null}
      <p className="text-xs text-slate-400">
        Log Viewer: pagina {pageInfo.page}, limite {pageInfo.limit}, total {pageInfo.total_records}
      </p>
      <LogsTable logs={filtered} />
      <Paginator
        page={pageInfo.page}
        limit={pageInfo.limit}
        totalRecords={pageInfo.total_records}
        hasPrev={Boolean(pageInfo.prev_page)}
        hasNext={Boolean(pageInfo.next_page)}
        onPageChange={(next) => setPage(Math.max(1, next))}
        onLimitChange={(nextLimit) => {
          setLimit(nextLimit);
          setPage(1);
        }}
        pageSizeOptions={[10, 25, 50, 100]}
      />
    </div>
  );
}

