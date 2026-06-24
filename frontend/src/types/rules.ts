export type RuleType = 'keyword_mapping' | 'pattern_list' | 'threshold';
export type RuleCategory = 'user_agent' | 'uri' | 'injection' | 'threshold';
export type MatchStrategy = 'substring_case_insensitive' | 'exact' | 'regex';

export interface RuleContent {
  type: RuleType;
  data: Record<string, unknown>;
  match_strategy: MatchStrategy;
}

export interface RuleMetadata {
  source: string;
  changed_by: string;
  change_reason: string;
  compatibility_version: string;
}

export interface ValidationRules {
  min_score: number;
  max_score: number;
  required_fields: string[];
}

export interface HeuristicRule {
  rule_id: string;
  rule_type: RuleType;
  category: RuleCategory;
  version: number;
  is_active: boolean;
  description: string;
  content: RuleContent;
  metadata: RuleMetadata;
  validation_rules: ValidationRules;
  created_at: string;
  updated_at: string;
}

export interface HeuristicRuleUpdate {
  rule_type?: RuleType;
  category?: RuleCategory;
  version?: number;
  is_active?: boolean;
  description?: string;
  content?: RuleContent;
  metadata?: RuleMetadata;
}

export interface RuleVersion {
  version_hash: string;
  created_at: string;
  is_active: boolean;
  rules_included: string[];
  changelog: string;
  deployed_by: string;
  deployment_timestamp?: string | null;
  rollback_url?: string | null;
}

export interface RulesListResponse {
  rules: HeuristicRule[];
  version_hash: string;
  total: number;
}

export interface RuleCreateResponse {
  rule_id: string;
  message: string;
  version_hash: string;
  created_at: string;
}

export interface RuleUpdateResponse {
  message: string;
  rule_id: string;
  updated_at: string;
}

export interface RuleDeleteResponse {
  message: string;
  rule_id: string;
}

export interface ValidateRulesResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
  tests_passed?: number;
  tests_total?: number;
}

export interface CreateVersionRequest {
  rules_included: string[];
  changelog?: string;
  deployed_by?: string;
}

export interface ActivateVersionResponse {
  message: string;
  active_version: string;
  deployed_at: string;
  rules_included: string[];
}

export interface RulesHealthResponse {
  status: string;
  cached: boolean;
  version_hash: string;
  last_updated?: string | null;
  source: string;
  total_active_rules: number;
}

export interface AuditLogResponse {
  total: number;
  offset: number;
  limit: number;
  entries: Array<Record<string, unknown>>;
}

