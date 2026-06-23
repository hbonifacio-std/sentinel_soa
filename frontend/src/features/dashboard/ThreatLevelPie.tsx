import {Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip} from 'recharts';
import type { TooltipProps } from 'recharts';
import { TooltipDivider, TooltipRow, TooltipShell } from '@/components/TooltipShell';
import type { ThreatLevelRow } from '@/types/api';

const LEVEL_META: Record<string, { color: string; emoji: string }> = {
  CRITICAL: { color: '#ef4444', emoji: '🔴' },
  HIGH: { color: '#f97316', emoji: '🟠' },
  MEDIUM: { color: '#eab308', emoji: '🟡' },
  LOW: { color: '#3b82f6', emoji: '🔵' },
};

type ThreatLevelWithPercentage = ThreatLevelRow & { percentage: number };

function formatPercentage(value: number) {
  return `${value.toFixed(1)}%`;
}

function renderLegendItem(value: string, entry: any) {
  const percentage = entry?.payload?.percentage ?? 0;

  return (<span style={ {color: '#94a3b8'}} > {value} {formatPercentage(percentage)} </span> )
}

function ThreatLevelTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) {
    return null;
  }

  const row = payload[0].payload as ThreatLevelWithPercentage | undefined;
  if (!row) {
    return null;
  }

  const meta = LEVEL_META[row._id] ?? { color: '#94a3b8', emoji: '⚪' };

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

export function ThreatLevelPie({ data }: Readonly<{ data: ThreatLevelRow[] }>) {
  const totalCount = data.reduce((acc, item) => acc + item.count, 0);
  const chartData: ThreatLevelWithPercentage[] = data.map((item) => ({
    ...item,
    percentage: totalCount > 0 ? (item.count / totalCount) * 100 : 0,
  }));

  return (
    <div className="h-72 rounded-lg border border-surface-border bg-surface-elevated p-3">
      <h3 className="mb-2 text-sm text-slate-300">Threat Level Distribution</h3>
      <ResponsiveContainer width="100%" height="90%">
        <PieChart>
          <Pie data={chartData} dataKey="count" nameKey="_id" outerRadius={90} innerRadius={60} paddingAngle={4}>
            {chartData.map((entry) => (
              <Cell key={entry._id} fill={(LEVEL_META[entry._id] ?? { color: '#94a3b8' }).color} />
            ))}
          </Pie>
          <Tooltip content={<ThreatLevelTooltip />} />
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

