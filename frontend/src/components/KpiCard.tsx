import type { LucideIcon } from 'lucide-react';

interface KpiCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
}

export function KpiCard({ title, value, subtitle, icon: Icon }: KpiCardProps) {
  return (
    <article className="rounded-lg border border-surface-border bg-surface-elevated p-4 transition hover:border-accent-cyan/50">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm text-slate-300">{title}</h3>
        <Icon size={16} className="text-accent-cyan" />
      </div>
      <p className="text-2xl font-semibold text-white">{value}</p>
      {subtitle ? <p className="mt-1 text-xs text-slate-400">{subtitle}</p> : null}
    </article>
  );
}

