import { useFilters } from '@/hooks/useFilters';
import { useSentinelStore } from '@/store/sentinelStore';

export function AlertsFilters() {
  const { filters, searchQuery, setFilter, setSearchQuery } = useFilters();
  const sourceIds = useSentinelStore((state) => state.sourceIds);
  const activeSourceId = useSentinelStore((state) => state.activeSourceId);
  const setActiveSourceId = useSentinelStore((state) => state.setActiveSourceId);

  return (
    <div className="grid gap-3 rounded-lg border border-surface-border bg-surface-elevated p-3 md:grid-cols-4">
      <input
        placeholder="Buscar IP, razonamiento, tactica"
        className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm"
        value={searchQuery}
        onChange={(event) => setSearchQuery(event.target.value)}
      />
      <select
        className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm"
        value={filters.threatLevel ?? ''}
        onChange={(event) => setFilter('threatLevel', (event.target.value || null) as typeof filters.threatLevel)}
      >
        <option value="">Threat level</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
      <select
        className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm"
        value={filters.status ?? ''}
        onChange={(event) => setFilter('status', (event.target.value || null) as typeof filters.status)}
      >
        <option value="">Status</option>
        <option value="pending">pending</option>
        <option value="reviewing">reviewing</option>
        <option value="resolved">resolved</option>
      </select>
      <select
        className="rounded border-surface-border bg-slate-900 px-3 py-2 text-sm"
        value={activeSourceId ?? ''}
        onChange={(event) => setActiveSourceId(event.target.value || null)}
      >
        {sourceIds.map((id) => (
          <option key={id} value={id}>
            {id}
          </option>
        ))}
      </select>
    </div>
  );
}
