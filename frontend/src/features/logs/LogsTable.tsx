import { useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { IpAddress } from '@/components/IpAddress';
import { formatBytes, formatDate } from '@/lib/formatters';
import { LogRowExpanded } from '@/features/logs/LogRowExpanded';
import type { LogEntry } from '@/types/logEntry';

interface LogsTableProps {
  logs: readonly LogEntry[];
}

export function LogsTable({ logs }: Readonly<LogsTableProps>) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);

  useEffect(() => {
    if (!selectedLog) {
      return;
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setSelectedLog(null);
      }
    }

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [selectedLog]);

  const rowVirtualizer = useVirtualizer({
    count: logs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 10,
  });

  const COLS = ['Timestamp', 'Source ID', 'Source IP', 'Method', 'Request URI', 'Status', 'Bytes', 'User Agent'] as const;

  return (
    <div className="rounded-lg border border-surface-border bg-surface-elevated">
      {/* Encabezado fijo fuera del contenedor scroll */}
      <div className="grid grid-cols-8 gap-2 border-b border-surface-border bg-surface-elevated px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
        {COLS.map((col) => (
          <span key={col}>{col}</span>
        ))}
      </div>

      {/* Filas virtualizadas */}
      <div ref={parentRef} className="h-[520px] overflow-auto">
        <div style={{ height: rowVirtualizer.getTotalSize(), position: 'relative' }}>
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const log = logs[virtualRow.index];
            if (!log) return null;
            return (
              <div
                key={log.id ?? virtualRow.index}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                className="border-b border-surface-border px-3 py-2 text-xs text-slate-300"
              >
                <button
                  className="grid w-full grid-cols-8 gap-2 text-left"
                  onClick={() => setSelectedLog(log)}
                >
                  <span>{log.timestamp ? formatDate(log.timestamp) : '-'}</span>
                  <span className="truncate" title={log.source_id ?? ''}>{log.source_id ?? '-'}</span>
                  <IpAddress value={log.source_ip ?? '-'} />
                  <span>{log.http_method ?? '-'}</span>
                  <span className="truncate" title={log.request_uri ?? ''}>{log.request_uri ?? '-'}</span>
                  <span>{log.response_code ?? '-'}</span>
                  <span>{formatBytes(log.bytes_sent ?? null)}</span>
                  <span className="truncate" title={log.user_agent ?? ''}>{log.user_agent ?? '-'}</span>
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {selectedLog ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4"
          onClick={() => setSelectedLog(null)}
          role="dialog"
          aria-modal="true"
        >
          <div
            className="max-h-[85vh] w-full max-w-5xl overflow-auto rounded-lg border border-surface-border bg-slate-950 p-3 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="mb-2 flex items-center justify-between">
              <p className="text-xs text-slate-300">Detalle completo del evento</p>
              <button
                className="rounded border border-surface-border px-2 py-1 text-xs text-slate-200"
                onClick={() => setSelectedLog(null)}
              >
                Cerrar
              </button>
            </div>
            <LogRowExpanded log={selectedLog} />
          </div>
        </div>
      ) : null}
    </div>
  );
}

