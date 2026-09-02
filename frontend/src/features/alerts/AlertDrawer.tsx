import { useState } from 'react';
import { MitreTag } from '@/components/MitreTag';
import { StatusChip } from '@/components/StatusChip';
import { ThreatBadge } from '@/components/ThreatBadge';
import { formatDate } from '@/lib/formatters';
import { MitigationTimeline } from '@/features/alerts/MitigationTimeline';
import { ReasoningBreakdown } from '@/features/alerts/ReasoningBreakdown';
import type { Threat } from '@/types/threat';

interface AlertDrawerProps {
  threat: Threat | null;
  isOpen: boolean;
  onClose: () => void;
  onReview: (id: string) => Promise<void>;
  onAddAction: (id: string, comment: string) => Promise<void>;
  onResolve: (id: string) => Promise<void>;
}

export function AlertDrawer({ threat, isOpen, onClose, onReview, onAddAction, onResolve }: AlertDrawerProps) {
  const [actionComment, setActionComment] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen || !threat) {
    return null;
  }

  const currentThreat = threat;

  const canAddActions = currentThreat.reviewed && !currentThreat.resolved;

  async function handleReview() {
    setIsSubmitting(true);
    try {
      await onReview(currentThreat.id);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleAddAction() {
    const comment = actionComment.trim();
    if (!comment || !canAddActions) {
      return;
    }

    setIsSubmitting(true);
    try {
      await onAddAction(currentThreat.id, comment);
      setActionComment('');
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleResolve() {
    setIsSubmitting(true);
    try {
      await onResolve(currentThreat.id);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <aside className="fixed inset-y-0 right-0 z-40 w-full max-w-xl overflow-auto border-l border-surface-border bg-slate-950 p-4 shadow-2xl">
      <button className="mb-3 rounded border border-surface-border px-2 py-1 text-xs" onClick={onClose}>
        Close
      </button>

      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <ThreatBadge level={threat.threat_level} size="md" />
          <StatusChip status={threat.status} />

          <span className="text-xs text-slate-400 border border-slate-400 rounded-full px-2.5 py-0.5">
              {threat.kill_chain_phase}
          </span>
          <span className="text-xs text-slate-400">{formatDate(threat.created_at_utc)}</span>
        </div>


        <div className="flex flex-wrap gap-2">
          <MitreTag id={threat.mitre_tactic_id ?? threat.details?.mitre_tactic_id} label={threat.mitre_tactic ?? threat.details?.mitre_tactic} />
          <MitreTag
            id={threat.mitre_technique_id ?? threat.details?.mitre_technique_id}
            label={threat.mitre_technique ?? threat.details?.mitre_technique}
          />
        </div>

         <section className="space-y-2 rounded border border-surface-border p-3">
          <h4 className="text-sm font-semibold">Targeted Asset</h4>
           <p className="text-xs text-slate-300">
             <span className="font-mono">{threat.targeted_asset}</span>

           </p>
        </section>

        <section className="space-y-2 rounded border border-surface-border p-3">
          <h4 className="text-sm font-semibold">Reasoning</h4>
          <ReasoningBreakdown
            indicators_found={threat.indicators_found}
            reasoning_summary={threat.reasoning_summary}
          />
        </section>

        <section className="space-y-2 rounded border border-surface-border p-3">
          <h4 className="text-sm font-semibold">Mitigation Timeline</h4>
          <MitigationTimeline
            recommendation={threat.recommendation}
            suggested_mitigations={threat.suggested_mitigations}
          />
        </section>

        <section className="space-y-3 rounded border border-surface-border p-3">
          <h4 className="text-sm font-semibold">Analyst Actions</h4>
          {threat.actions?.length ? (
            <ul className="space-y-2 text-xs text-slate-300">
              {threat.actions.map((action, index) => (
                <li key={`${action.created_at_utc}-${index}`} className="rounded border border-surface-border px-2 py-1">
                  <p>{action.comment}</p>
                  <p className="text-[11px] text-slate-400">{formatDate(action.created_at_utc)}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-400">No actions recorded.</p>
          )}

          <textarea
            className="w-full rounded border border-surface-border bg-slate-900 px-2 py-1 text-sm"
            rows={3}
            placeholder={canAddActions ? 'Write an action...' : 'Mark the alert as reviewed to add actions'}
            value={actionComment}
            onChange={(event) => setActionComment(event.target.value)}
            disabled={!canAddActions || isSubmitting}
          />
          <button
            className="rounded border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50"
            onClick={handleAddAction}
            disabled={!canAddActions || !actionComment.trim() || isSubmitting}
          >
            Add action
          </button>
        </section>

        <div className="flex gap-2">
          <button
            className="rounded border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200"
            onClick={handleReview}
            disabled={Boolean(threat.reviewed) || isSubmitting}
          >
            {threat.reviewed ? 'Reviewed' : 'Mark as reviewed'}
          </button>
          <button
            className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200"
            onClick={handleResolve}
            disabled={Boolean(threat.resolved) || isSubmitting}
          >
            {threat.resolved ? 'Resolved' : 'Mark as resolved'}
          </button>
        </div>
      </div>
    </aside>
  );
}
