import { Activity, AlertTriangle, Shield, Zap } from 'lucide-react';
import { KpiCard } from '@/components/KpiCard';
import type { Threat } from '@/types/threat';
import { parseISO, differenceInMinutes,formatDuration,addMinutes,intervalToDuration } from 'date-fns';

interface KpiGridProps {
  threats: Threat[];
}

export function KpiGrid({ threats }: KpiGridProps) {
  const active_threat = threats.filter((t) => t.status !== 'resolved').length;
  const critical_threat = threats.filter((t) => (t.threat_level === 'CRITICAL'||t.threat_level=='HIGH') && t.status !== 'resolved').length;
  const { totalMinutesResolved, resolvedCount } = threats.reduce(
  (acc, t) => {
    // Verificamos de forma segura que existan AMBAS fechas
    if (t.created_at_utc && t.resolved_at_utc) {
      const start = parseISO(t.created_at_utc);
      const end = parseISO(t.resolved_at_utc);
      acc.totalMinutesResolved += differenceInMinutes(end,start);
      acc.resolvedCount += 1;
    }
    return acc;
  },
  { totalMinutesResolved: 0, resolvedCount: 0 }
);

function formatMinutesToReadableTime(totalMinutes: number): string {
  if (totalMinutes === 0) return '0m';

  const baseDate = new Date(0); // Fecha base neutra (1970-01-01)
  const futureDate = addMinutes(baseDate, totalMinutes); // Le sumamos los minutos del promedio

  // Extrae un objeto con { days, hours, minutes } exactos
  const duration = intervalToDuration({ start: baseDate, end: futureDate });

  // Lo formatea a texto amigable: "1 d 3 h 15 m" o "1 día 3 horas"
  return formatDuration(duration, {
    format: ['days', 'hours', 'minutes'],
  });
}
// Calculamos el promedio dividiendo ÚNICAMENTE entre las que de verdad se resolvieron
const averageScore = formatMinutesToReadableTime(resolvedCount > 0 ? totalMinutesResolved / resolvedCount : 0);

  const topAttacker = threats[0]?.source_ip ?? '-';

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <KpiCard title="Total Threats" value={threats.length} icon={Shield} />
      <KpiCard title="Active Threats" value={active_threat} icon={AlertTriangle} />
      <KpiCard title="Active Critical Threats" value={critical_threat} icon={AlertTriangle} />
      <KpiCard title="Mean Time to Mitigate (MTTR)" value={averageScore} icon={Activity} />
    </div>
  );
}

