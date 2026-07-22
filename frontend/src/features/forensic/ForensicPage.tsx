import { FormEvent, useMemo, useState } from 'react';
import { MarkdownRenderer } from '@/components/MarkdownRenderer';
import { useForensicAnalysis } from '@/features/forensic/hooks/useForensicAnalysis';
import { useForensicHistory, useForensicReport } from '@/features/forensic/hooks/useForensicHistory';
import { useForensicModels } from '@/features/forensic/hooks/useForensicModels';
import { useSentinelStore } from '@/store/sentinelStore';
import { ForensicHighlights } from './components/ForensicHighlights';

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
    return historyQuery.data?.results.find((item) => item.analysis_id === selectedReportId) ?? null;
  }, [historyQuery.data?.results, reportQuery.data, selectedReportId]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedQuery = query.trim();
    if (normalizedQuery.length < 3) {
      return;
    }

    const report = await analyzeMutation.mutateAsync({
      query: normalizedQuery,
      source_id: sourceId,
      page: 1,
      limit: 25,
      model_id: selectedModelId || undefined,
    });
    setSelectedReportId(report.analysis_id);
  }

  const history = historyQuery.data?.results ?? [];
  const pageInfo = historyQuery.data?.info;

  return (
    <div className="grid min-h-[70vh] grid-cols-1 gap-4 xl:grid-cols-[340px_1fr]">
      <section className="space-y-3 rounded border border-surface-border bg-surface-elevated/40 p-4">
        <h2 className="text-sm font-semibold text-slate-100">Analisis Forense</h2>
        <form className="space-y-3" onSubmit={(event) => void handleSubmit(event)}>
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-400">Modelo IA</label>
            <select
              className="w-full rounded border border-surface-border bg-slate-950/50 p-2 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              value={selectedModelId}
              onChange={(e) => setSelectedModelId(e.target.value)}
            >
              <option value="">Default (Tenant: {defaultModelId})</option>
              {Object.entries(availableModels).map(([id, m]) => (
                <option key={id} value={id}>
                  {id} ({m.provider} — {m.model_name})
                </option>
              ))}
            </select>
          </div>

          <textarea
            className="min-h-20 w-full rounded border border-surface-border bg-slate-950/50 p-2 text-sm text-slate-100"
            placeholder="Consulta forense (IP, URI, user agent, patron...)"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <button
            type="submit"
            className="w-full rounded border border-accent-cyan/60 bg-accent-glow px-3 py-2 text-sm text-cyan-200 disabled:opacity-60"
            disabled={analyzeMutation.isPending || query.trim().length < 3}
          >
            {analyzeMutation.isPending ? 'Analizando...' : 'Ejecutar analisis'}
          </button>
        </form>

        <div className="space-y-2">
          <p className="text-xs text-slate-400">Historial</p>
          {historyQuery.isLoading ? <p className="text-xs text-slate-400">Cargando historial...</p> : null}
          {historyQuery.error instanceof Error ? (
            <p className="text-xs text-red-400">{historyQuery.error.message}</p>
          ) : null}
          <div className="space-y-1">
            {history.map((item) => (
              <button
                key={item.analysis_id}
                className="w-full rounded border border-surface-border px-2 py-1 text-left text-xs hover:bg-slate-900"
                onClick={() => setSelectedReportId(item.analysis_id)}
                type="button"
              >
                <p className="font-medium text-slate-200">{item.query}</p>
                <p className="text-slate-400">{new Date(item.created_at_utc).toLocaleString()}</p>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 pt-1 text-xs text-slate-400">
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
            <select
              className="ml-auto rounded border border-surface-border bg-slate-950/50 px-2 py-1"
              value={limit}
              onChange={(event) => {
                setLimit(Number(event.target.value));
                setPage(1);
              }}
            >
              {[10, 25, 50].map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
        </div>
      </section>

      <section className="space-y-3 rounded border border-surface-border bg-surface-elevated/40 p-4">
        <h3 className="text-sm font-semibold text-slate-100">Reporte seleccionado</h3>
        {!selectedReport ? <p className="text-sm text-slate-400">Selecciona un reporte del historial.</p> : null}
        {selectedReport ? (
          <>
            <div className="grid grid-cols-1 gap-2 text-xs text-slate-300 sm:grid-cols-4">
              <div className="rounded border border-surface-border p-2">
                <p className="text-slate-400">Consulta</p>
                <p className="truncate">{selectedReport.query}</p>
              </div>
              <div className="rounded border border-surface-border p-2">
                <p className="text-slate-400">Coincidencias</p>
                <p>{selectedReport.total_matches}</p>
              </div>
              <div className="rounded border border-surface-border p-2">
                <p className="text-slate-400">Fuente</p>
                <p>{selectedReport.source_id ?? 'todas'}</p>
              </div>
              <div className="rounded border border-surface-border p-2">
                <p className="text-slate-400">Modelo IA</p>
                <p className="truncate text-cyan-300">
                  {selectedReport.llm_model_used
                    ? `${selectedReport.llm_provider_used}/${selectedReport.llm_model_used}`
                    : 'Default Global'}
                </p>
              </div>
            </div>
            <ForensicHighlights highlights={selectedReport.highlights} />
            <MarkdownRenderer content={selectedReport.markdown_report} />
          </>
        ) : null}
      </section>
    </div>
  );
}

