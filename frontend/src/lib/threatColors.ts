import type { ThreatLevel } from '@/types/threat';

export const threatColorMap: Record<ThreatLevel, string> = {
  CRITICAL: 'text-threat-critical border-threat-critical/40 bg-threat-critical/10',
  HIGH: 'text-threat-high border-threat-high/40 bg-threat-high/10',
  MEDIUM: 'text-threat-medium border-threat-medium/40 bg-threat-medium/10',
  LOW: 'text-threat-low border-threat-low/40 bg-threat-low/10',
};

