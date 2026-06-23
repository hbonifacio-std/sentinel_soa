import { format, parseISO } from 'date-fns';
import {Area, AreaChart, Brush, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts';
import type { TooltipProps } from 'recharts';
import { TooltipDivider, TooltipRow, TooltipShell } from '@/components/TooltipShell';
import type { TimelineRow } from '@/types/api';

function truncateUserAgent(value: string | null) {
  if (!value) {
    return '—';
  }

  return value.length > 28 ? `${value.slice(0, 28)}…` : value;
}

function formatTooltipTimestamp(timestamp: string) {
  const parsed = parseISO(timestamp);
  if (Number.isNaN(parsed.getTime())) {
    return timestamp;
  }

  return format(parsed, "d MMM yyyy · HH:mm 'UTC'");
}

function TimelineTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) {
    return null;
  }

  const row = payload[0].payload as TimelineRow | undefined;
  if (!row) {
    return null;
  }

  const otherCount = Math.max(row.count - row.criticalCount, 0);
  let responseCodeColor = '#e2e8f0';
  if (row.dominantResponseCode != null) {
    responseCodeColor = row.dominantResponseCode < 400 ? '#22c55e' : '#ef4444';
  }

  return (
    <TooltipShell accentColor="#06b6d4">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '14px', fontWeight: 700 }}>{formatTooltipTimestamp(row.timestamp)}</span>
      </div>
      <TooltipDivider />
      <TooltipRow label="Total alertas" value={row.count} color="#06b6d4" />
      <TooltipRow label="Críticas" value={row.criticalCount} color="#ef4444" />
      <TooltipRow label="Otras" value={otherCount} color="#eab308" />
      <TooltipDivider />
      <TooltipRow label="IP Principal" value={row.dominantIp ?? '—'} color="#cbd5e1" />
      <TooltipRow label="User-Agent" value={truncateUserAgent(row.dominantUserAgent)} color="#cbd5e1" />
      <TooltipRow label="HTTP dominante" value={row.dominantResponseCode ?? '—'} color={responseCodeColor} />
    </TooltipShell>
  );
}

export function AttackTimeline({ data }: Readonly<{ data: TimelineRow[] }>) {
  return (
    <div className="h-72 rounded-lg border border-surface-border bg-surface-elevated p-3">
      <h3 className="mb-2 text-sm text-slate-300">Attack Timeline</h3>
      <ResponsiveContainer width="100%" height="90%">
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis
          dataKey="timestamp"
           tickFormatter={(tick, index) => {
            try {
              const date = parseISO(tick);

              // 1. Si es el primer tick del gráfico o es exactamente la medianoche (00:00)
              if (index === 0 || date.getHours() === 0 && date.getMinutes() === 0) {
                // Muestra algo como: "20 Jun" o "20/06"
                return format(date, 'dd MMM');
              }

              // 2. Para el resto de horas del mismo día, solo muestra la hora
              return format(date, 'HH:mm');
            } catch {
              return tick;
            }
          }}
              minTickGap={20} // Importante para que no se encima la fecha con la hora de al lado
              stroke="#94a3b8"
              fontSize={11}
          />
          <YAxis />
          <Tooltip content={<TimelineTooltip />} cursor={{ stroke: '#06b6d4', strokeWidth: 1, strokeDasharray: '4 4' }} />
          <Area type="monotone" dataKey="count" stroke="#06b6d4" fill="#06b6d422" />
          <Area type="monotone" dataKey="criticalCount" stroke="#ef4444" fill="#ef444422" />

        <Brush
            dataKey="timestamp"
            height={30}
            stroke="#334155"        // Color del borde del control
            fill="#1e293b"          // Color de fondo del control (combina con tu modo oscuro)
            tickFormatter={(t) => format(parseISO(t), 'HH:mm')}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

