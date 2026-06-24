import { apiFetch } from '@/lib/apiClient';
import type {
  ActivateVersionResponse,
  AuditLogResponse,
  CreateVersionRequest,
  HeuristicRule,
  HeuristicRuleUpdate,
  RuleCreateResponse,
  RuleDeleteResponse,
  RuleUpdateResponse,
  RuleVersion,
  RulesHealthResponse,
  RulesListResponse,
  ValidateRulesResponse,
} from '@/types/rules';

const basePath = '/api/v1/rules';

export async function listRules(includeInactive = false): Promise<RulesListResponse> {
  const query = new URLSearchParams({ include_inactive: String(includeInactive) }).toString();
  return apiFetch<RulesListResponse>(`${basePath}?${query}`);
}

export async function getRule(ruleId: string): Promise<HeuristicRule> {
  return apiFetch<HeuristicRule>(`${basePath}/${encodeURIComponent(ruleId)}`);
}

export async function createRule(rule: HeuristicRule): Promise<RuleCreateResponse> {
  return apiFetch<RuleCreateResponse>(basePath, {
    method: 'POST',
    body: JSON.stringify(rule),
  });
}

export async function updateRule(ruleId: string, updates: HeuristicRuleUpdate): Promise<RuleUpdateResponse> {
  return apiFetch<RuleUpdateResponse>(`${basePath}/${encodeURIComponent(ruleId)}`, {
    method: 'PATCH',
    body: JSON.stringify(updates),
  });
}

export async function deleteRule(ruleId: string, user = 'admin', reason = 'Rule deactivated'): Promise<RuleDeleteResponse> {
  const query = new URLSearchParams({ user, reason }).toString();
  return apiFetch<RuleDeleteResponse>(`${basePath}/${encodeURIComponent(ruleId)}?${query}`, {
    method: 'DELETE',
  });
}

export async function validateRules(rules: HeuristicRule[]): Promise<ValidateRulesResponse> {
  return apiFetch<ValidateRulesResponse>(`${basePath}/validate`, {
    method: 'POST',
    body: JSON.stringify({ rules }),
  });
}

export async function getRulesHealth(): Promise<RulesHealthResponse> {
  return apiFetch<RulesHealthResponse>(`${basePath}/health`);
}

export async function listVersions(limit = 50): Promise<RuleVersion[]> {
  const query = new URLSearchParams({ limit: String(limit) }).toString();
  return apiFetch<RuleVersion[]>(`${basePath}/versions?${query}`);
}

export async function createVersion(payload: CreateVersionRequest): Promise<RuleVersion> {
  return apiFetch<RuleVersion>(`${basePath}/versions`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function activateVersion(versionHash: string): Promise<ActivateVersionResponse> {
  return apiFetch<ActivateVersionResponse>(`${basePath}/versions/activate/${encodeURIComponent(versionHash)}`, {
    method: 'POST',
  });
}

export async function getAuditLog(ruleId?: string, limit = 50, offset = 0): Promise<AuditLogResponse> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (ruleId) {
    query.set('rule_id', ruleId);
  }
  return apiFetch<AuditLogResponse>(`${basePath}/audit-log?${query.toString()}`);
}

