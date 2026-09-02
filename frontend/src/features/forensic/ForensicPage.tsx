import { FormEvent, useMemo, useState } from 'react';
import { useForensicAnalysis } from '@/features/forensic/hooks/useForensicAnalysis';
import { useForensicHistory, useForensicReport } from '@/features/forensic/hooks/useForensicHistory';
import { useForensicModels } from '@/features/forensic/hooks/useForensicModels';
import { useSentinelStore } from '@/store/sentinelStore';
import { ForensicHighlights } from './components/ForensicHighlights';
import ChatView from './components/ChatView';

export default function ForensicPage() {
  const sourceId = useSentinelStore((state) => state.activeSourceId);
  const [query, setQuery] = useState('');
  const [selectedModelId, setSelectedModelId] = useState<string>('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);

  const historyQuery = useForensicHistory(sourceId, page, limit);
  const reportQuery = useForensicReport(selectedReportId);
  const modelsQuery = useForensicModels();
  const analyzeMutation = useForensicAnalysis(sourceId, page, limit);

  const availableModels = modelsQuery.data?.available_models ?? {};
  const defaultModelId = modelsQuery.data?.default_model_id ?? 'default';

  const selectedReport = useMemo(() => {
    if (reportQuery.data) {
      return reportQuery.data;
    }
    return historyQuery.data?.results.find((item) => item.session_id === selectedReportId) ?? null;
  }, [historyQuery.data?.results, reportQuery.data, selectedReportId]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedQuery = query.trim();
    if (normalizedQuery.length < 3) {
      return;
    }

    const session = await analyzeMutation.mutateAsync({
      query: normalizedQuery,
      source_id: sourceId,
      model_id: selectedModelId || undefined,
    });
    setSelectedReportId(session.session_id ?? null);
  }

  const history = historyQuery.data?.results ?? [];
  const pageInfo = historyQuery.data?.info;

  return (
    <div className="h-[calc(100vh-4rem)] grid grid-cols-1 gap-4 xl:grid-cols-[260px_1fr]">
      <aside className="space-y-3 rounded border border-surface-border bg-surface-elevated/40 p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">Conversaciones</h2>
          <button
            type="button"
            className="text-xs rounded border border-surface-border px-2 py-1 hover:bg-slate-900"
            onClick={() => {
              setSelectedReportId(null);
              setQuery('');
            }}
          >
            Nueva
          </button>
        </div>

        <div className="space-y-2">
          {historyQuery.isLoading ? <p className="text-xs text-slate-400">Cargando conversaciones...</p> : null}
          {historyQuery.error instanceof Error ? (
            <p className="text-xs text-red-400">{historyQuery.error.message}</p>
          ) : null}

          <div className="space-y-1 overflow-y-auto max-h-[60vh]">
            {history.length === 0 ? (
              <p className="text-xs text-slate-400">Aún no hay conversaciones. Presiona "Nueva" para iniciar.</p>
            ) : (
              history.map((item) => {
                const lastUser = [...(item.messages ?? [])].reverse().find((m) => m.role === 'user');
                const title = lastUser ? lastUser.content : item.messages?.[0]?.content ?? item.session_id;
                return (
                  <button
                    key={item.session_id}
                    className="w-full rounded border border-surface-border px-2 py-2 text-left text-xs hover:bg-slate-900"
                    onClick={() => setSelectedReportId(item.session_id ?? null)}
                    type="button"
                  >
                    <p className="font-medium text-slate-200 truncate">{title}</p>
                    <p className="text-slate-400">{new Date(item.created_at_utc).toLocaleString()}</p>
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 pt-2 text-xs text-slate-400">
          <button
            type="button"
            className="rounded border border-surface-border px-2 py-1 disabled:opacity-50"
            onClick={() => setPage((prev) => Math.max(1, prev - 1))}
            disabled={!pageInfo?.prev_page}
          >
            Prev
          </button>
          <span>Pag {pageInfo?.page ?? page}</span>
          <button
            type="button"
            className="rounded border border-surface-border px-2 py-1 disabled:opacity-50"
            onClick={() => setPage((prev) => prev + 1)}
            disabled={!pageInfo?.next_page}
          >
            Next
          </button>
        </div>
      </aside>

      <section className="space-y-3 rounded border border-surface-border bg-surface-elevated/40 p-4 flex flex-col">
        <header className="flex items-start justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Chat Forense</h3>
            <p className="text-xs text-slate-400">
              {selectedReport ? `Session: ${selectedReport.session_id}` : 'Nueva conversación'}
            </p>
          </div>

          <div className="flex items-center gap-2">
            {analyzeMutation.isPending ? (
              <span className="inline-flex items-center gap-2 rounded bg-yellow-600 px-2 py-1 text-xs font-medium text-black">
                <span className="h-2 w-2 rounded-full bg-white animate-pulse" /> Analizando
              </span>
            ) : null}
          </div>
        </header>

        <main className="mt-3 flex-1 overflow-hidden">
          {!selectedReport ? (
            <div className="h-full rounded border border-dashed border-surface-border p-6 text-sm text-slate-400">
              Inicia la conversación escribiendo tu mensaje en el campo inferior. Verás visualizaciones del análisis cuando la respuesta llegue (spinners, tarjetas destacadas y timeline).
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-2 text-xs text-slate-300 sm:grid-cols-4">
                <div className="rounded border border-surface-border p-2">
                  <p className="text-slate-400">Client</p>
                  <p>{selectedReport.client_id}</p>
                </div>
                <div className="rounded border border-surface-border p-2">
                  <p className="text-slate-400">Creado</p>
                  <p>{new Date(selectedReport.created_at_utc).toLocaleString()}</p>
                </div>
                <div className="rounded border border-surface-border p-2">
                  <p className="text-slate-400">Estado</p>
                  <p className="truncate text-cyan-300">{selectedReport.is_active ? 'Activa' : 'Cerrada'}</p>
                </div>
                <div className="rounded border border-surface-border p-2">
                  <p className="text-slate-400">Session</p>
                  <p className="truncate">{selectedReport.session_id}</p>
                </div>
              </div>

              <div className="mt-4 flex flex-col gap-4 flex-1 overflow-hidden">
                <ForensicHighlights highlights={selectedReport.highlighted} />

                {/* Chat area: ChatView contains the single scrollable messages region and the floating input */}
                <div className="flex-1 relative">
                  <ChatView
                    messages={selectedReport.messages}
                    query={query}
                    setQuery={setQuery}
                    selectedModelId={selectedModelId}
                    setSelectedModelId={setSelectedModelId}
                    analyzeMutation={analyzeMutation}
                    availableModels={availableModels}
                    defaultModelId={defaultModelId}
                    handleSubmit={handleSubmit}
                  />
                </div>
              </div>
            </>
          )}
        </main>

      </section>
    </div>
  );
}

