import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  activateVersion,
  createRule,
  createVersion,
  deleteRule,
  getRulesHealth,
  listRules,
  listVersions,
  updateRule,
  validateRules,
} from '@/lib/rulesApi';
import { ApiError } from '@/lib/apiClient';
import { useAuthStore } from '@/store/authStore';
import type {
  HeuristicRule,
  HeuristicRuleUpdate,
  MatchStrategy,
  RuleCategory,
  RuleType,
  RulesHealthResponse,
  RuleVersion,
  ValidateRulesResponse,
} from '@/types/rules';

const ruleTypeOptions: RuleType[] = ['keyword_mapping', 'pattern_list', 'threshold'];
const categoryOptions: RuleCategory[] = ['user_agent', 'uri', 'injection', 'threshold'];
const strategyOptions: MatchStrategy[] = ['substring_case_insensitive', 'exact', 'regex'];

type EditorMode = 'create' | 'edit';

interface RuleDraft {
  rule_id: string;
  rule_type: RuleType;
  category: RuleCategory;
  version: number;
  is_active: boolean;
  description: string;
  match_strategy: MatchStrategy;
  contentDataText: string;
  source: string;
  changed_by: string;
  change_reason: string;
  compatibility_version: string;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (typeof error.detail === 'string' && error.detail.trim()) {
      return error.detail;
    }

    if (error.status === 403) {
      return 'You do not have permission to perform this action.';
    }

    if (error.status === 401) {
      return 'Your session has expired. Please log in again.';
    }
  }

  if (!(error instanceof Error)) {
    return 'Unexpected error';
  }

  return error.message;
}

function buildDefaultDraft(changedBy = 'admin'): RuleDraft {
  return {
    rule_id: '',
    rule_type: 'keyword_mapping',
    category: 'user_agent',
    version: 1,
    is_active: true,
    description: '',
    match_strategy: 'substring_case_insensitive',
    contentDataText: '{\n  "example": 20\n}',
    source: 'frontend',
    changed_by: changedBy,
    change_reason: 'Initial creation from UI',
    compatibility_version: '1.0.0',
  };
}

function ruleToDraft(rule: HeuristicRule): RuleDraft {
  return {
    rule_id: rule.rule_id,
    rule_type: rule.rule_type,
    category: rule.category,
    version: rule.version,
    is_active: rule.is_active,
    description: rule.description,
    match_strategy: rule.content.match_strategy,
    contentDataText: JSON.stringify(rule.content.data, null, 2),
    source: rule.metadata.source,
    changed_by: rule.metadata.changed_by,
    change_reason: rule.metadata.change_reason,
    compatibility_version: rule.metadata.compatibility_version,
  };
}

function draftToRule(draft: RuleDraft): HeuristicRule {
  const contentData = JSON.parse(draft.contentDataText) as Record<string, unknown>;
  const now = new Date().toISOString();

  return {
    rule_id: draft.rule_id.trim(),
    rule_type: draft.rule_type,
    category: draft.category,
    version: Math.max(1, Number(draft.version)),
    is_active: draft.is_active,
    description: draft.description.trim(),
    content: {
      type: draft.rule_type,
      data: contentData,
      match_strategy: draft.match_strategy,
    },
    metadata: {
      source: draft.source.trim() || 'frontend',
      changed_by: draft.changed_by.trim() || 'admin',
      change_reason: draft.change_reason.trim() || 'Updated from UI',
      compatibility_version: draft.compatibility_version.trim() || '1.0.0',
    },
    validation_rules: {
      min_score: 0,
      max_score: 100,
      required_fields: ['rule_id', 'category'],
    },
    created_at: now,
    updated_at: now,
  };
}

function ruleToUpdatePayload(draft: RuleDraft): HeuristicRuleUpdate {
  const parsed = draftToRule(draft);
  return {
    rule_type: parsed.rule_type,
    category: parsed.category,
    version: parsed.version,
    is_active: parsed.is_active,
    description: parsed.description,
    content: parsed.content,
    metadata: parsed.metadata,
  };
}

export default function RulesPage() {
  const currentUser = useAuthStore((state) => state.user);
  const currentTenantId = currentUser?.client_id ?? null;
  const isAdmin = currentUser?.role === 'admin';
  const [rules, setRules] = useState<HeuristicRule[]>([]);
  const [versions, setVersions] = useState<RuleVersion[]>([]);
  const [health, setHealth] = useState<RulesHealthResponse | null>(null);
  const [validation, setValidation] = useState<ValidateRulesResponse | null>(null);

  const [includeInactive, setIncludeInactive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editorMode, setEditorMode] = useState<EditorMode>('create');
  const [draft, setDraft] = useState<RuleDraft>(buildDefaultDraft());
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  const [versionRuleIds, setVersionRuleIds] = useState('');
  const [versionChangelog, setVersionChangelog] = useState('Created from frontend UI');
  const [versionDeployedBy, setVersionDeployedBy] = useState('admin');

  const activeRules = useMemo(() => rules.filter((rule) => rule.is_active), [rules]);

  const refreshData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesResponse, versionsResponse, healthResponse] = await Promise.all([
        listRules(includeInactive),
        listVersions(100),
        getRulesHealth(),
      ]);
      setRules(rulesResponse.rules);
      setVersions(versionsResponse);
      setHealth(healthResponse);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [includeInactive]);

  useEffect(() => {
    void refreshData();
  }, [refreshData]);

  function isGlobalRule(rule: HeuristicRule): boolean {
    return !rule.tenant_id || rule.tenant_id === '*';
  }

  function canMutateRule(rule: HeuristicRule): boolean {
    if (!isAdmin || isGlobalRule(rule)) {
      return false;
    }

    if (!currentTenantId) {
      return true;
    }

    return rule.tenant_id === currentTenantId;
  }

  function openCreateEditor() {
    if (!isAdmin) {
      setError('Only an admin can create rules.');
      return;
    }

    setEditorMode('create');
    setDraft(buildDefaultDraft(currentUser?.username ?? 'admin'));
    setSelectedRuleId(null);
    setEditorOpen(true);
  }

  function openEditEditor(rule: HeuristicRule) {
    if (!canMutateRule(rule)) {
      setError('You can only edit custom rules owned by your tenant.');
      return;
    }

    setEditorMode('edit');
    setDraft(ruleToDraft(rule));
    setSelectedRuleId(rule.rule_id);
    setEditorOpen(true);
  }

  async function handleSubmitEditor() {
    if (!isAdmin) {
      setError('Only an admin can modify rules.');
      return;
    }

    setError(null);
    setActionMessage(null);

    try {
      if (!draft.rule_id.trim()) {
        throw new Error('The rule_id field is mandatory.');
      }

      if (!draft.description.trim()) {
        throw new Error('The description field is mandatory.');
      }

      if (editorMode === 'create') {
        const payload = draftToRule(draft);
        await createRule(payload);
        setActionMessage(`Rule created: ${payload.rule_id}`);
      } else if (selectedRuleId) {
        const payload = ruleToUpdatePayload(draft);
        await updateRule(selectedRuleId, payload);
        setActionMessage(`Updated rule: ${selectedRuleId}`);
      }

      setEditorOpen(false);
      await refreshData();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleDeactivate(rule: HeuristicRule) {
    if (!canMutateRule(rule)) {
      setError('You can only deactivate custom rules owned by your tenant.');
      return;
    }

    const reason = window.prompt('Reason for deactivation', 'Rule deactivated from frontend');
    if (!reason) {
      return;
    }
    const user = window.prompt('User applying the change', 'admin') || 'admin';

    try {
      await deleteRule(rule.rule_id, user, reason);
      setActionMessage(`Rule disabled: ${rule.rule_id}`);
      await refreshData();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleValidateBundle() {
    try {
      const result = await validateRules(activeRules);
      setValidation(result);
      if (result.valid) {
        setActionMessage('Successful validation of the active bundle.');
      }
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleCreateVersion() {
    if (!isAdmin) {
      setError('Only an admin can create versions.');
      return;
    }

    const rulesIncluded = versionRuleIds
      .split(',')
      .map((ruleId) => ruleId.trim())
      .filter(Boolean);

    if (rulesIncluded.length === 0) {
      setError('You must enter at least one rule_id to create a version.');
      return;
    }

    try {
      await createVersion({
        rules_included: rulesIncluded,
        changelog: versionChangelog,
        deployed_by: versionDeployedBy,
      });
      setActionMessage('Version successfully created.');
      await refreshData();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleActivateVersion(versionHash: string) {
    if (!isAdmin) {
      setError('Only an admin can activate versions.');
      return;
    }

    try {
      await activateVersion(versionHash);
      setActionMessage(`Active version: ${versionHash}`);
      await refreshData();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  function useActiveRulesForVersion() {
    const ids = activeRules.map((rule) => rule.rule_id).join(', ');
    setVersionRuleIds(ids);
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-surface-border bg-surface-elevated p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold">Rules Management</h2>
            <p className="text-xs text-slate-400">Heuristic rule CRUD and version management</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button className="rounded border border-surface-border px-3 py-1.5 text-sm" onClick={() => void refreshData()}>
              Refresh
            </button>
            {isAdmin ? (
              <button className="rounded border border-accent-cyan/50 bg-accent-glow px-3 py-1.5 text-sm text-cyan-300" onClick={openCreateEditor}>
                New rule
              </button>
            ) : null}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-300">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={includeInactive}
              onChange={(event) => setIncludeInactive(event.target.checked)}
            />
            Include inactive ones
          </label>
          {health ? (
            <>
              <span>Estado: {health.status}</span>
              <span>Cache: {health.cached ? 'hit' : 'miss'}</span>
              <span>Version activa: {health.version_hash}</span>
              <span>Reglas activas: {health.total_active_rules}</span>
            </>
          ) : null}
          {!isAdmin ? <span className="text-amber-300">Modo analyst: solo lectura operativa y validacion.</span> : null}
        </div>

        {loading ? <p className="mt-2 text-sm text-slate-400">Cargando reglas...</p> : null}
        {error ? <p className="mt-2 text-sm text-red-400">{error}</p> : null}
        {actionMessage ? <p className="mt-2 text-sm text-emerald-400">{actionMessage}</p> : null}
      </div>

      <div className="rounded-lg border border-surface-border bg-surface-elevated p-4">
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Reglas ({rules.length})</h3>
          <button className="rounded border border-surface-border px-2 py-1 text-xs" onClick={() => void handleValidateBundle()}>
            Validate active bundle
          </button>
        </div>
        <p className="mb-2 text-xs text-slate-400">Global rules are read-only. Only tenant custom rules can be edited.</p>

        {validation ? (
          <div className="mb-3 rounded border border-surface-border bg-slate-950/40 p-3 text-xs">
            <p className={validation.valid ? 'text-emerald-300' : 'text-amber-300'}>
              Validacion: {validation.valid ? 'valida' : 'con errores'}
              {typeof validation.tests_passed === 'number' && typeof validation.tests_total === 'number'
                ? ` (${validation.tests_passed}/${validation.tests_total} tests)`
                : ''}
            </p>
            {validation.errors.length > 0 ? <p className="mt-1 text-red-300">Errores: {validation.errors.join(' | ')}</p> : null}
            {validation.warnings.length > 0 ? <p className="mt-1 text-amber-300">Warnings: {validation.warnings.join(' | ')}</p> : null}
          </div>
        ) : null}

        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="text-slate-400">
              <tr>
                <th className="px-2 py-2">rule_id</th>
                <th className="px-2 py-2">tipo</th>
                <th className="px-2 py-2">categoria</th>
                <th className="px-2 py-2">scope</th>
                <th className="px-2 py-2">version</th>
                <th className="px-2 py-2">activo</th>
                <th className="px-2 py-2">updated_at</th>
                <th className="px-2 py-2">actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.rule_id} className="border-t border-surface-border">
                  <td className="px-2 py-2 font-mono">{rule.rule_id}</td>
                  <td className="px-2 py-2">{rule.rule_type}</td>
                  <td className="px-2 py-2">{rule.category}</td>
                  <td className="px-2 py-2">
                    <span className={isGlobalRule(rule) ? 'rounded border border-slate-500/40 px-2 py-0.5 text-slate-300' : 'rounded border border-cyan-500/40 px-2 py-0.5 text-cyan-300'}>
                      {isGlobalRule(rule) ? 'Global' : 'Custom'}
                    </span>
                  </td>
                  <td className="px-2 py-2">{rule.version}</td>
                  <td className="px-2 py-2">{rule.is_active ? 'si' : 'no'}</td>
                  <td className="px-2 py-2">{new Date(rule.updated_at).toLocaleString()}</td>
                  <td className="px-2 py-2">
                    {canMutateRule(rule) ? (
                      <div className="flex gap-2">
                        <button className="rounded border border-surface-border px-2 py-1" onClick={() => openEditEditor(rule)}>
                          Edit
                        </button>
                        <button
                          className="rounded border border-red-500/40 px-2 py-1 text-red-300 disabled:opacity-50"
                          onClick={() => void handleDeactivate(rule)}
                          disabled={!rule.is_active}
                        >
                          Deactivate
                        </button>
                      </div>
                    ) : isGlobalRule(rule) ? (
                      <span className="text-slate-500">Global rule (read-only)</span>
                    ) : (
                      <span className="text-slate-500">No editing permissions</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-surface-border bg-surface-elevated p-4">
          <h3 className="text-sm font-semibold">Create version</h3>
          <p className="mt-1 text-xs text-slate-400">Use comma-separated `rule_id`s.</p>
          <div className="mt-3 space-y-2 text-sm">
            <textarea
              className="h-24 w-full rounded border border-surface-border bg-slate-950 px-2 py-2 font-mono text-xs"
              value={versionRuleIds}
              onChange={(event) => setVersionRuleIds(event.target.value)}
              placeholder="malicious_ua_keywords_v1, sensitive_uris_v1"
            />
            <div className="flex gap-2">
              <input
                className="w-full rounded border border-surface-border bg-slate-950 px-2 py-1"
                value={versionDeployedBy}
                onChange={(event) => setVersionDeployedBy(event.target.value)}
                placeholder="deployed_by"
              />
              <button className="rounded border border-surface-border px-2 py-1 text-xs" onClick={useActiveRulesForVersion}>
                Use active
              </button>
            </div>
            <input
              className="w-full rounded border border-surface-border bg-slate-950 px-2 py-1"
              value={versionChangelog}
              onChange={(event) => setVersionChangelog(event.target.value)}
              placeholder="changelog"
            />
            {isAdmin ? (
              <button className="rounded border border-accent-cyan/50 bg-accent-glow px-3 py-1.5 text-sm text-cyan-300" onClick={() => void handleCreateVersion()}>
                Create Version
              </button>
            ) : null}
          </div>
        </div>

        <div className="rounded-lg border border-surface-border bg-surface-elevated p-4">
          <h3 className="text-sm font-semibold">Versions ({versions.length})</h3>
          <div className="mt-2 max-h-72 space-y-2 overflow-auto pr-1">
            {versions.map((version) => (
              <div key={version.version_hash} className="rounded border border-surface-border bg-slate-950/40 p-2 text-xs">
                <p className="font-mono text-slate-200">{version.version_hash}</p>
                <p className="text-slate-400">{new Date(version.created_at).toLocaleString()}</p>
                <p className="text-slate-300">rules: {version.rules_included.join(', ')}</p>
                <p className="text-slate-300">deployed_by: {version.deployed_by}</p>
                <div className="mt-2 flex items-center gap-2">
                  <span className={version.is_active ? 'text-emerald-300' : 'text-slate-400'}>
                    {version.is_active ? 'Activa' : 'Inactiva'}
                  </span>
                  {isAdmin ? (
                    <button
                      className="rounded border border-surface-border px-2 py-1 disabled:opacity-50"
                      disabled={version.is_active}
                      onClick={() => void handleActivateVersion(version.version_hash)}
                    >
                      Activate
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {editorOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4" role="dialog" aria-modal="true">
          <div className="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-lg border border-surface-border bg-slate-950 p-4">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">{editorMode === 'create' ? 'Nueva regla' : `Editar ${selectedRuleId}`}</h3>
              <button className="rounded border border-surface-border px-2 py-1 text-xs" onClick={() => setEditorOpen(false)}>
                close
              </button>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-xs">
                rule_id
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.rule_id}
                  disabled={editorMode === 'edit'}
                  onChange={(event) => setDraft((prev) => ({ ...prev, rule_id: event.target.value }))}
                />
              </label>

              <label className="text-xs">
                descripcion
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.description}
                  onChange={(event) => setDraft((prev) => ({ ...prev, description: event.target.value }))}
                />
              </label>

              <label className="text-xs">
                rule_type
                <select
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.rule_type}
                  onChange={(event) =>
                    setDraft((prev) => ({
                      ...prev,
                      rule_type: event.target.value as RuleType,
                    }))
                  }
                >
                  {ruleTypeOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="text-xs">
                category
                <select
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.category}
                  onChange={(event) =>
                    setDraft((prev) => ({
                      ...prev,
                      category: event.target.value as RuleCategory,
                    }))
                  }
                >
                  {categoryOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="text-xs">
                match_strategy
                <select
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.match_strategy}
                  onChange={(event) =>
                    setDraft((prev) => ({
                      ...prev,
                      match_strategy: event.target.value as MatchStrategy,
                    }))
                  }
                >
                  {strategyOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="text-xs">
                version
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  type="number"
                  min={1}
                  value={draft.version}
                  onChange={(event) => setDraft((prev) => ({ ...prev, version: Number(event.target.value) }))}
                />
              </label>

              <label className="text-xs md:col-span-2">
                <span className="mr-2">is_active</span>
                <input
                  type="checkbox"
                  checked={draft.is_active}
                  onChange={(event) => setDraft((prev) => ({ ...prev, is_active: event.target.checked }))}
                />
              </label>

              <label className="text-xs">
                source
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.source}
                  onChange={(event) => setDraft((prev) => ({ ...prev, source: event.target.value }))}
                />
              </label>

              <label className="text-xs">
                changed_by
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.changed_by}
                  onChange={(event) => setDraft((prev) => ({ ...prev, changed_by: event.target.value }))}
                />
              </label>

              <label className="text-xs md:col-span-2">
                change_reason
                <input
                  className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-2 py-1"
                  value={draft.change_reason}
                  onChange={(event) => setDraft((prev) => ({ ...prev, change_reason: event.target.value }))}
                />
              </label>

              <label className="text-xs md:col-span-2">
                content.data (JSON)
                <textarea
                  className="mt-1 h-52 w-full rounded border border-surface-border bg-slate-900 px-2 py-1 font-mono text-xs"
                  value={draft.contentDataText}
                  onChange={(event) => setDraft((prev) => ({ ...prev, contentDataText: event.target.value }))}
                />
              </label>
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <button className="rounded border border-surface-border px-3 py-1.5 text-sm" onClick={() => setEditorOpen(false)}>
                Cancel
              </button>
              <button
                className="rounded border border-accent-cyan/50 bg-accent-glow px-3 py-1.5 text-sm text-cyan-300"
                onClick={() => void handleSubmitEditor()}
              >
                {editorMode === 'create' ? 'Crear regla' : 'Guardar cambios'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
