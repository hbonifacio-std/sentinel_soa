import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

interface MarkdownRendererProps {
  content: string;
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  return (
    <div className="prose prose-sm prose-invert max-w-none rounded border border-surface-border bg-slate-950/40 p-4 text-xs tracking-wide">
      <ReactMarkdown 
        remarkPlugins={[remarkGfm]}
        components={{
        
          h2: ({node, ...props}) => (
            <h2 className="text-xl font-bold text-red-400 mt-6 mb-3 uppercase tracking-wider border-b border-slate-800/60 pb-1" {...props} />
          ),
    
          h3: ({node, ...props}) => (
            <h3 className="text-sm font-bold text-slate-100 mt-5 mb-2 tracking-wide" {...props} />
          ),
          p: ({node, ...props}) => <p className="text-xs text-slate-400 leading-relaxed mb-3" {...props} />,
          table: ({node, ...props}) => <div className="overflow-x-auto my-3"><table className="min-w-full divide-y divide-slate-800 text-left text-[11px]" {...props} /></div>,
          thead: ({node, ...props}) => <thead className="bg-slate-900/50 text-slate-400" {...props} />,
          th: ({node, ...props}) => <th className="px-3 py-2 font-mono font-medium" {...props} />,
          td: ({node, ...props}) => <td className="px-3 py-1.5 border-b border-slate-900 font-mono text-slate-300" {...props} />,
          code: ({node, ...props}) => <code className="bg-slate-900 text-amber-400 px-1 py-0.5 rounded text-[11px] font-mono border border-slate-800" {...props} />,
          blockquote: ({node, ...props}) => <blockquote className="border-l-2 border-blue-500 bg-blue-950/20 px-3 py-2 rounded-r my-3 text-slate-400 italic" {...props} />
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}