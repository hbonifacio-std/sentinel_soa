import React from 'react';
import { LoadingScreen } from '@/components/LoadingScreen';
import { useLogs } from '@/hooks/useLogs';
import { useStats } from '@/hooks/useStats';
import { useThreats } from '@/hooks/useThreats';
import { useSentinelStore } from '@/store/sentinelStore';
import { AttackTimeline } from '@/features/dashboard/AttackTimeline';
import { KpiGrid } from '@/features/dashboard/KpiGrid';
import { MitreTacticsChart } from '@/features/dashboard/MitreTacticsChart';
import { ThreatLevelPie } from '@/features/dashboard/ThreatLevelPie';
import { KillChainPhasePie } from '@/features/dashboard/KillChainPhasePie';


export default function DashboardPage() {
  const sourceId = useSentinelStore((state: { activeSourceId: string | null }) => state.activeSourceId);
  const { threats, loading: loadingThreats, error: threatsError } = useThreats(sourceId);
  const { logs, loading: loadingLogs, error: logsError } = useLogs(sourceId, { page: 1, limit: 100 });
  const {stats, timelineData, mitreTactics, threatLevelData, killChainPhaseData, loading: loadingStats, error: statsError } = useStats(
    sourceId,
    threats,
    logs,
  );
  const error = threatsError ?? logsError ?? statsError;

  if (loadingThreats || loadingLogs || loadingStats) {
    return <LoadingScreen />;
  }

  if (error) {
    return <div className="rounded border border-red-500/40 bg-red-500/10 p-4 text-red-200">{error.message}</div>;
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <KpiGrid threats={threats} />
      <div className="grid gap-4 xl:grid-cols-2">
        <AttackTimeline data={timelineData} />
        <ThreatLevelPie data={threatLevelData} />
        <MitreTacticsChart data={mitreTactics} />
        <KillChainPhasePie data={killChainPhaseData} />
      </div>
    </div>
  );
}
