import { Outlet } from 'react-router-dom';
import { Sidebar } from '@/components/Sidebar';
import { useSourceIds } from '@/hooks/useSourceIds';
import { useSentinelStore } from '@/store/sentinelStore';

function App() {
  const { sourceIds, activeSourceId, loadingSources, error } = useSourceIds();
  const setActiveSourceId = useSentinelStore((state) => state.setActiveSourceId);


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

