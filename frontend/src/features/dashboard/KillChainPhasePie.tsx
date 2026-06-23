import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend, type TooltipProps } from 'recharts';
import {TooltipDivider, TooltipRow, TooltipShell} from "@/components/TooltipShell";
import {KillChainPhase} from "@/types/threat";

 // Usaremos 'Unknown' para agrupar los valores null

// 2. Interfaz estricta para los datos que recibe el componente
export interface KillChainPhaseRow {
  _id: KillChainPhase;
  count: number;
  activeCount: number;
  mitigatedCount: number;
}

type KillChainWithPercentage = KillChainPhaseRow & { percentage: number };

// 3. Diccionario exclusivo indexado de forma estricta
const KILL_CHAIN_META: Record<KillChainPhase, { color: string; emoji: string }> = {
  'Reconnaissance': { color: '#3b82f6', emoji: '🔍' },
  'Weaponization': { color: '#8b5cf6', emoji: '📦' },
  'Delivery': { color: '#6366f1', emoji: '📨' },
  'Exploitation': { color: '#f43f5e', emoji: '💥' },
  'Installation': { color: '#f59e0b', emoji: '🧩' },
  'Command and Control': { color: '#0ea5e9', emoji: '📡' },
  'Actions on Objectives': { color: '#ef4444', emoji: '🎯' },
  'Unknown': { color: '#64748b', emoji: '⚪' },
};

function formatPercentage(value: number) {
  return `${value.toFixed(1)}%`;
}

function renderLegendItem(value: KillChainPhase, entry: any) {
  const percentage = entry?.payload?.percentage ?? 0;
  return (
    <span style={{ color: '#94a3b8' }}>
      {value} ({formatPercentage(percentage)})
    </span>
  );
}

// 4. Tooltip con tipado fuerte
function KillChainTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) {
    return null;
  }

  const row = payload[0].payload as KillChainWithPercentage | undefined;
  if (!row) {
    return null;
  }

  const meta = KILL_CHAIN_META[row._id] ?? KILL_CHAIN_META.Unknown;

  return (
    <TooltipShell accentColor={meta.color}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '14px', fontWeight: 700 }}>
          {meta.emoji} {row._id}
        </span>
      </div>
      <TooltipDivider />
      <TooltipRow label="Total alertas" value={row.count} color="#e2e8f0" />
      <TooltipRow label="% del total" value={formatPercentage(row.percentage)} color="#93c5fd" />
      <TooltipRow label="Activas 🔥" value={row.activeCount} color="#ef4444" />
      <TooltipRow label="Mitigadas ✓" value={row.mitigatedCount} color="#22c55e" />
    </TooltipShell>
  );
}

// 5. Componente final optimizado
export function KillChainPhasePie({ data }: Readonly<{ data: KillChainPhaseRow[] }>) {
  const totalCount = data.reduce((acc, item) => acc + item.count, 0);

  const chartData: KillChainWithPercentage[] = data.map((item) => ({
    ...item,
    // Nos aseguramos de que si el _id viene vacío o null desde el map del hook, se asigne a 'Unknown'
    _id: item._id || 'Unknown',
    percentage: totalCount > 0 ? (item.count / totalCount) * 100 : 0,
  }));

  return (
    <div className="h-72 rounded-lg border border-surface-border bg-surface-elevated p-3">
      <h3 className="mb-2 text-sm text-slate-300">Cyber Kill Chain Phase</h3>
      <ResponsiveContainer width="100%" height="90%">
        <PieChart>
          <Pie data={chartData} dataKey="count" nameKey="_id" outerRadius={90} innerRadius={60} paddingAngle={4}>
            {chartData.map((entry) => {
              const meta = KILL_CHAIN_META[entry._id] ?? KILL_CHAIN_META.Unknown;
              return <Cell key={entry._id} fill={meta.color} />;
            })}
          </Pie>
          <Tooltip content={<KillChainTooltip />} />
          <Legend
            layout="vertical"
            align="left"
            verticalAlign="middle"
            iconType="square"
            iconSize={16}
            wrapperStyle={{ fontSize: '13px', paddingLeft: '15px' }}
            formatter={renderLegendItem}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}