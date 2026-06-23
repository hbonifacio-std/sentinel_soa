import type { LogEntry } from '@/types/logEntry';

interface LogsFiltersProps {
  search: string;
  method: string;
  status: string;
  onSearch: (value: string) => void;
  onMethod: (value: string) => void;
  onStatus: (value: string) => void;
  logs: LogEntry[];
}

export function LogsFilters({ search, method, status, onSearch, onMethod, onStatus, logs }: LogsFiltersProps) {
  const methods = Array.from(new Set(logs.map((l) => l.http_method))).sort();

  return (
    <div className="grid gap-3 rounded-lg border border-surface-border bg-surface-elevated p-3 md:grid-cols-3">
      <input
        className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm"
        placeholder="Buscar IP / URI"
        value={search}
        onChange={(event) => onSearch(event.target.value)}
      />
      <select className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm" value={method} onChange={(e) => onMethod(e.target.value)}>
        <option value="">Metodo HTTP</option>
        {methods.map((item) => (
          <option key={item} value={item}>
            {item}
          </option>
        ))}
      </select>
      <select className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm" value={status} onChange={(e) => onStatus(e.target.value)}>
        <option value="">Status code</option>
        <option value="2xx">2xx</option>
        <option value="4xx">4xx</option>
        <option value="5xx">5xx</option>
      </select>
    </div>
  );
}

