import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { TooltipProps } from 'recharts';
import { TooltipDivider, TooltipRow, TooltipShell } from '@/components/TooltipShell';
import type { MitreTacticRow } from '@/types/api';

function truncatePath(value: string) {
  return value.length > 32 ? `${value.slice(0, 32)}…` : value;
}

function MitreTacticTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) {
    return null;
  }

  const row = payload[0].payload as MitreTacticRow | undefined;
  if (!row) {
    return null;
  }

  const visibleTechniques = row.techniques.slice(0, 4);
  const hiddenTechniques = Math.max(row.techniques.length - visibleTechniques.length, 0);

  return (
    <TooltipShell accentColor="#f97316">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '14px', fontWeight: 700 }}>{row._id}</span>
        {row.tacticId ? (
          <span
            style={{
              background: '#1e3a5f',
              color: '#f97316',
              borderRadius: '4px',
              padding: '1px 6px',
              fontSize: '11px',
              fontWeight: 700,
            }}
          >
            {row.tacticId}
          </span>
        ) : null}
      </div>
      <TooltipDivider />
      <TooltipRow label="Eventos" value={row.count} color="#f97316" />
      <TooltipDivider />
      <div style={{ color: '#94a3b8', marginBottom: '4px' }}>Técnicas detectadas:</div>
      {visibleTechniques.length ? (
        visibleTechniques.map((technique) => (
          <div key={technique.id} style={{ marginTop: '4px', color: '#e2e8f0' }}>
            · {technique.name} <span style={{ color: '#94a3b8' }}>({technique.id})</span>
          </div>
        ))
      ) : (
        <div style={{ marginTop: '4px', color: '#94a3b8' }}>Sin detalle de técnicas en esta fuente.</div>
      )}
      {hiddenTechniques > 0 ? <div style={{ marginTop: '4px', color: '#94a3b8' }}>+{hiddenTechniques} más</div> : null}
      {row.topPaths.length ? (
        <>
          <TooltipDivider />
          <div style={{ color: '#94a3b8', marginBottom: '4px' }}>Paths más atacados:</div>
          {row.topPaths.slice(0, 3).map((path) => (
            <div key={path} style={{ marginTop: '4px', color: '#e2e8f0' }}>
              {truncatePath(path)}
            </div>
          ))}
        </>
      ) : null}
    </TooltipShell>
  );
}

export function MitreTacticsChart({ data }: Readonly<{ data: MitreTacticRow[] }>) {
  return (
    <div className="h-72 rounded-lg border border-surface-border bg-surface-elevated p-3">
      <h3 className="mb-2 text-sm text-slate-300">MITRE tactics</h3>
      <ResponsiveContainer width="100%" height="90%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis type="number" />
          <YAxis dataKey="_id" type="category" width={120} />
          <Tooltip content={<MitreTacticTooltip />} cursor={{ fill: '#f9731611' }} />
          <Bar dataKey="count" fill="#f97316" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

