import { JsonViewer } from '@/components/JsonViewer';
import type { LogEntry } from '@/types/logEntry';

export function LogRowExpanded({ log }: { log: LogEntry }) {
  return (
    <div className="rounded border border-surface-border bg-slate-900/40 p-2">
      <JsonViewer data={log.raw ?? log} />
    </div>
  );
}

