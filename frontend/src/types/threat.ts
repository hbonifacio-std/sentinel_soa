export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertStatus = 'pending' | 'reviewing' | 'resolved';

export type KillChainPhase =
  | 'Reconnaissance'
  | 'Weaponization'
  | 'Delivery'
  | 'Exploitation'
  | 'Installation'
  | 'Command and Control'
  | 'Actions on Objectives'
  | 'Unknown';
export interface SuggestedMitigationItem {
  action: string;
  target: string;
  reason: string;
  severity: string;
  automation_ready: boolean;
}

export interface AlertAction {
  comment: string;
  created_at_utc: string;
}

export interface Threat {
  id: string;
  source_id?: string;
  source_ip: string;
  threat_level: ThreatLevel;
  threat_score: number;
  targeted_asset?: string | null;
  kill_chain_phase: KillChainPhase;
  mitre_tactic?: string | null;
  mitre_tactic_id?: string | null;
  mitre_technique?: string | null;
  mitre_technique_id?: string | null;
  mitre_sub_technique?: string | null;
  mitre_sub_technique_id?: string | null;
  indicators_found?: string[];
  reasoning_summary?: string;
  recommendation?: string;
  suggested_mitigations?: SuggestedMitigationItem[];
  created_at_utc: string;
  reviewed?: boolean;
  resolved?: boolean;
  resolved_at_utc?: string | null;
  actions?: AlertAction[];
  status: AlertStatus;
  details?: Partial<Threat>;
}

