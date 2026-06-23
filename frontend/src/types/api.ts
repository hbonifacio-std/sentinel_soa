import type { AlertAction, ThreatLevel } from '@/types/threat';

export interface PageInfo {
  total_records: number;
  page: number;
  limit: number;
  next_page: string | null;
  prev_page: string | null;
}

export interface PaginatedResponse<T> {
  info: PageInfo;
  results: T[];
}

export interface ThreatLevelCount {
  _id: ThreatLevel;
  count: number;
}

export interface TechniqueRef {
  name: string;
  id: string;
}

export interface MitreTacticRow {
  _id: string;
  tacticId?: string;
  count: number;
  techniques: TechniqueRef[];
  topPaths: string[];
}

export interface TimelineRow {
  timestamp: string;
  count: number;
  criticalCount: number;
  dominantIp: string | null;
  dominantUserAgent: string | null;
  dominantResponseCode: number | null;
}

export interface ThreatLevelRow {
  _id: ThreatLevel;
  count: number;
  activeCount: number;
  mitigatedCount: number;
}

export interface KillChainCount {
  _id: string;
  count: number;
}

export interface AttackerCount {
  _id: string;
  count: number;
}

export interface StatsResponse {
  threat_levels: ThreatLevelCount[];
  kill_chain_phases: KillChainCount[];
  top_attackers: AttackerCount[];
  mitre_tactics?: KillChainCount[];
}

export interface ActionPayload {
  comment: string;
}

export interface AlertWorkflowResponse {
  report_id: string;
  reviewed: boolean;
  resolved: boolean;
  actions: AlertAction[];
}

