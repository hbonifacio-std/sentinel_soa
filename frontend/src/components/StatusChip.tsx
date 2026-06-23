import type { AlertStatus } from '@/types/threat';
import { cn } from '@/lib/cn';

const statusColor: Record<AlertStatus, string> = {
  pending: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300',
  reviewing: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
  resolved: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
};

export function StatusChip({ status }: { status: AlertStatus }) {
  return <span className={cn('rounded border px-2 py-0.5 text-xs', statusColor[status])}>{status}</span>;
}

