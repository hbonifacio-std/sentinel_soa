import { IpAddress } from '@/components/IpAddress';
import { StatusChip } from '@/components/StatusChip';
import { ThreatBadge } from '@/components/ThreatBadge';
import { formatDate } from '@/lib/formatters';
import type { Threat } from '@/types/threat';

interface AlertsTableProps {
  threats: Threat[];
  onSelect: (id: string) => void;
}

export function AlertsTable({ threats, onSelect }: AlertsTableProps) {
  return (
    <div className="overflow-hidden rounded-lg border border-surface-border bg-surface-elevated">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-900/70 text-xs uppercase text-slate-300">
          <tr>
            <th className="px-3 py-2">Level</th>
            <th className="px-3 py-2">Kill Chain Phase</th>
            <th className="px-3 py-2">Source IP</th>
            <th className="px-3 py-2">Tactic</th>
            <th className="px-3 py-2">Score</th>
            <th className="px-3 py-2">Actions</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((threat) => (
            <tr
              key={threat._id}
              className="cursor-pointer border-t border-surface-border text-slate-200 transition hover:bg-slate-900/70"
              onClick={() => onSelect(threat._id)}
            >
              <td className="px-3 py-2"><ThreatBadge level={threat.threat_level} /></td>
              <td className="px-3 py-2 text-xs text-slate-300">{threat.kill_chain_phase ?? '-'}</td>
              <td className="px-3 py-2"><IpAddress value={threat.source_ip} /></td>
              <td className="px-3 py-2">{threat.mitre_tactic ?? '-'}</td>
              <td className="px-3 py-2">{threat.threat_score.toFixed(1)}</td>
              <td className="px-3 py-2">{threat.actions?.length ?? 0}</td>
              <td className="px-3 py-2"><StatusChip status={threat.status} /></td>
              <td className="px-3 py-2 text-xs text-slate-400">{formatDate(threat.created_at_utc)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

