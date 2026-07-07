import { useEffect, useMemo, useState } from 'react';
import { AlertDrawer } from '@/features/alerts/AlertDrawer';
import { AlertsFilters } from '@/features/alerts/AlertsFilters';
import { AlertsTable } from '@/features/alerts/AlertsTable';
import { useAlertAction } from '@/hooks/useAlertAction';
import { useFilters } from '@/hooks/useFilters';
import { useThreats } from '@/hooks/useThreats';
import { useSentinelStore } from '@/store/sentinelStore';

export default function AlertsPage() {
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const sourceId = useSentinelStore((state) => state.activeSourceId);
  const selectedThreatId = useSentinelStore((state) => state.selectedThreatId);
  const selectThreat = useSentinelStore((state) => state.selectThreat);
  const { threats, pageInfo, loading, error } = useThreats(sourceId, { page, limit });
  const { applyFilters } = useFilters();
  const { markAsReviewed, addAction, resolveReport } = useAlertAction(sourceId);

  useEffect(() => {
    setPage(1);
  }, [sourceId]);

  const filtered = useMemo(() => applyFilters(threats), [threats, applyFilters]);
  const selectedThreat = filtered.find((threat) => threat.id === selectedThreatId) ?? null;

  async function handleReview(id: string) {
    await markAsReviewed(id);
  }

  async function handleAddAction(id: string, comment: string) {
    await addAction(id, comment);
  }

  async function handleResolve(id: string) {
    await resolveReport(id);
  }

  return (
    <div className="space-y-4">
      <AlertsFilters />
      {loading ? <p className="text-sm text-slate-400">Cargando alertas...</p> : null}
      {error ? <p className="text-sm text-red-400">{error.message}</p> : null}
      <p className="text-xs text-slate-400">
        Alert Center: pagina {pageInfo.page}, limite {pageInfo.limit}, total {pageInfo.total_records}
      </p>
      <AlertsTable
        threats={filtered}
        onSelect={selectThreat}
        pageInfo={pageInfo}
        onPageChange={(next) => setPage(next)}
        onLimitChange={(nextLimit) => {
          setLimit(nextLimit);
          setPage(1);
        }}
      />
      <AlertDrawer
        threat={selectedThreat}
        isOpen={Boolean(selectedThreatId)}
        onClose={() => selectThreat(null)}
        onReview={handleReview}
        onAddAction={handleAddAction}
        onResolve={handleResolve}
      />
    </div>
  );
}

