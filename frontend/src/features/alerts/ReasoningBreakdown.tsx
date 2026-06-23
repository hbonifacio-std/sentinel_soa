interface ReasoningBreakdownProps {
  readonly indicators_found?: string[];
  readonly reasoning_summary?: string;
}

export function ReasoningBreakdown({ indicators_found, reasoning_summary }: Readonly<ReasoningBreakdownProps>) {
  const hasIndicators = Array.isArray(indicators_found) && indicators_found.length > 0;
  const hasSummary = typeof reasoning_summary === 'string' && reasoning_summary.trim().length > 0;

  if (!hasIndicators && !hasSummary) {
    return <p className="text-xs text-slate-400">No reasoning information available.</p>;
  }

  return (
    <div className="space-y-3">
      {hasIndicators && (
        <div>
          <h5 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Detected indicators
          </h5>
          <ul className="space-y-1">
            {indicators_found?.map((indicator, index) => (
              <li
                key={`ind-${index}-${indicator.slice(0, 15)}`}
                className="rounded bg-slate-900/60 px-2 py-1 text-xs text-slate-300"
              >
                {indicator}
              </li>
            ))}
          </ul>
        </div>
      )}

      {hasSummary && (
        <div className="rounded border border-surface-border bg-slate-900/40 px-3 py-2">
          <h5 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Heuristic summary
          </h5>
          <p className="text-xs text-slate-300">{reasoning_summary}</p>
        </div>
      )}
    </div>
  );
}

