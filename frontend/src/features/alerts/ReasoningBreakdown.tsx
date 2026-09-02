import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

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
            Reasoning summary
          </h5>
          <div className="prose prose-invert prose-sm max-w-none text-xs">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                h1: ({ node: _node, children, ...props }) => (
                  <h1 className="mb-3 mt-4 text-sm font-semibold uppercase tracking-[0.18em] text-cyan-300 first:mt-0" {...props}>
                    {children}
                  </h1>
                ),
                h2: ({ node: _node, children, ...props }) => (
                  <h2 className="mb-3 mt-4 text-sm font-semibold uppercase tracking-[0.18em] text-cyan-300 first:mt-0" {...props}>
                    {children}
                  </h2>
                ),
                h3: ({ node: _node, children, ...props }) => (
                  <h3 className="mb-2 mt-4 text-sm font-semibold text-slate-100 first:mt-0" {...props}>
                    {children}
                  </h3>
                ),
                h4: ({ node: _node, children, ...props }) => (
                  <h4 className="mb-2 mt-3 text-xs font-semibold uppercase tracking-wide text-slate-200 first:mt-0" {...props}>
                    {children}
                  </h4>
                ),
                p: ({ node: _node, ...props }) => <p className="whitespace-pre-wrap leading-relaxed text-slate-200" {...props} />,
                ul: ({ node: _node, ...props }) => <ul className="my-2 list-disc space-y-2 pl-5" {...props} />,
                ol: ({ node: _node, ...props }) => <ol className="my-2 list-decimal space-y-2 pl-5" {...props} />,
                li: ({ node: _node, ...props }) => <li className="leading-relaxed text-slate-200" {...props} />,
                strong: ({ node: _node, ...props }) => <strong className="font-semibold text-slate-100" {...props} />,
                code: ({ node: _node, className, children, ...props }) => {
                  const isBlock = typeof className === 'string' && className.length > 0;

                  return isBlock ? (
                    <code
                      className="block whitespace-pre-wrap rounded border border-slate-800 bg-slate-950/70 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-200"
                      {...props}
                    >
                      {children}
                    </code>
                  ) : (
                    <code className="rounded bg-slate-900 px-1 py-0.5 font-mono text-[11px] text-cyan-200" {...props}>
                      {children}
                    </code>
                  );
                },
                pre: ({ node: _node, ...props }) => <pre className="my-2 overflow-x-auto rounded border border-slate-800 bg-slate-950/70 p-3" {...props} />,
                blockquote: ({ node: _node, ...props }) => (
                  <blockquote className="my-3 border-l-2 border-cyan-500/70 pl-3 italic text-slate-300" {...props} />
                ),
              }}
            >
              {reasoning_summary}
            </ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
