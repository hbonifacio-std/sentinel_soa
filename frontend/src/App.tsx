import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '@/components/Sidebar';
import { apiFetch } from '@/lib/apiClient';
import { useSentinelStore } from '@/store/sentinelStore';

function App() {
  const [loadingSources, setLoadingSources] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const sourceIds = useSentinelStore((state) => state.sourceIds);
  const activeSourceId = useSentinelStore((state) => state.activeSourceId);
  const setSourceIds = useSentinelStore((state) => state.setSourceIds);
  const setActiveSourceId = useSentinelStore((state) => state.setActiveSourceId);

  useEffect(() => {
    async function loadSourceIds() {
      setLoadingSources(true);
      setError(null);
      try {
        const ids = await apiFetch<string[]>('/api/v1/analytics/source_ids');
        setSourceIds(ids);
        if (ids.length > 0) {
          setActiveSourceId(ids[0]);
        }
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoadingSources(false);
      }
    }

    void loadSourceIds();
  }, [setActiveSourceId, setSourceIds]);

  return (
    <div className="flex h-screen bg-surface-base text-slate-100">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="border-b border-surface-border bg-surface-elevated/60 p-4 backdrop-blur">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-lg font-semibold">Sentinel SOA - SOC Dashboard</h1>
            <select
              className="rounded border-surface-border bg-slate-900 px-3 py-1.5 text-sm"
              value={activeSourceId ?? ''}
              onChange={(event) => setActiveSourceId(event.target.value || null)}
              disabled={loadingSources}
            >
              {sourceIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            {error ? <span className="text-sm text-red-400">{error}</span> : null}
          </div>
        </header>
        <section className="min-h-0 flex-1 overflow-auto p-4">
          <Outlet />
        </section>
      </main>
    </div>
  );
}

export default App;

