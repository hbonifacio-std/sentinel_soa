import { cn } from '@/lib/cn';
import { threatColorMap } from '@/lib/threatColors';
import type { ThreatLevel } from '@/types/threat';

interface ThreatBadgeProps {
  level: ThreatLevel;
  size?: 'sm' | 'md';
}

export function ThreatBadge({ level, size = 'sm' }: ThreatBadgeProps) {
  return (
    <span
      aria-label={`Threat level: ${level}`}
      className={cn(
        'inline-flex items-center rounded border px-2 py-0.5 font-mono uppercase tracking-wide',
        size === 'sm' ? 'text-[10px]' : 'text-xs',
        threatColorMap[level],
      )}
    >
      {level}
    </span>
  );
}

