import type { SuggestedMitigationItem } from '@/types/threat';

interface MitigationTimelineProps {
  recommendation?: string;
  suggested_mitigations?: SuggestedMitigationItem[];
}

const SEVERITY_STYLES: Record<string, string> = {
  high: 'border-red-500/40 bg-red-500/10 text-red-300',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
  low: 'border-green-500/40 bg-green-500/10 text-green-300',
};

export function MitigationTimeline({ recommendation, suggested_mitigations }: MitigationTimelineProps) {
  const hasMitigations = Array.isArray(suggested_mitigations) && suggested_mitigations.length > 0;
  const hasRecommendation = typeof recommendation === 'string' && recommendation.trim().length > 0;

  if (!hasMitigations && !hasRecommendation) {
    return <p className="text-xs text-slate-400">No suggested mitigations.</p>;
  }

  return (
    <div className="space-y-4">
      {hasMitigations && (
        <div className="space-y-2">
          <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Automated actions
          </h5>
          {suggested_mitigations!.map((item, index) => {
            const severityClass = SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES['medium'];
            return (
              <div
                key={index}
                className={`rounded border px-3 py-2 text-xs ${severityClass}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold uppercase tracking-wide">{item.action.replace(/_/g, ' ')}</span>
                  {item.automation_ready && (
                    <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 text-[10px] font-medium text-cyan-300">
                      Auto-ready
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-slate-300">
                  Target: <span className="font-mono">{item.target}</span>
                </p>
                <p className="mt-0.5 text-slate-400">{item.reason}</p>
              </div>
            );
          })}
        </div>
      )}

      {hasRecommendation && (
        <div>
          <h5 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Response plan
          </h5>
          <div className="rounded border border-surface-border bg-slate-900/40 px-3 py-2">
            <pre className="whitespace-pre-wrap text-xs text-slate-300">{recommendation}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
