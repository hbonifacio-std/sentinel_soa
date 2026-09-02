import React, { useEffect, useRef } from 'react';
import type { ChatMessage } from '@/types/forensic';
import { MarkdownRenderer } from '@/components/MarkdownRenderer';

interface Props {
  messages: ChatMessage[];
  query: string;
  setQuery: (v: string) => void;
  selectedModelId: string;
  setSelectedModelId: (v: string) => void;
  analyzeMutation: any;
  availableModels: Record<string, any>;
  defaultModelId: string;
  handleSubmit: (e: React.FormEvent<HTMLFormElement>) => Promise<void> | void;
  sessionId: string | null;
  pendingUserMessage?: (ChatMessage & { error?: boolean; attempts?: number; idempotencyKey?: string; errorInfo?: { error_code?: string; detail?: string } }) | null;
  onRetry?: () => void;
}

export default function ChatView({
  messages,
  query,
  setQuery,
  selectedModelId,
  setSelectedModelId,
  analyzeMutation,
  availableModels,
  defaultModelId,
  handleSubmit,
  sessionId,
  pendingUserMessage = null,
  onRetry,
}: Props) {
  const messagesRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    // Auto-scroll to bottom when messages change
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [messages]);

  const sorted = (messages || []).slice().sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return (
    <div className="h-full flex flex-col relative">
      {/* Messages area: single scrollbar here */}
      <div ref={messagesRef} className="flex-1 overflow-auto pr-3 space-y-4 pb-28 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-slate-900" style={{maxHeight: '60vh'}}>
        {sorted.length === 0 ? (
          <p className="text-sm text-slate-400">No hay mensajes en esta sesión.</p>
        ) : (
          <>
            {sorted.map((m, idx) => {
              const isUser = m.role === 'user';
              const isAssistant = m.role === 'assistant';

              const bubbleClasses = isUser
                ? 'ml-auto max-w-[65%] rounded-lg rounded-br-md border border-accent-cyan/40 bg-gradient-to-br from-cyan-900/80 to-cyan-800/60 p-3 text-sm text-slate-100 shadow-sm'
                : 'mr-auto max-w-[65%] rounded-lg rounded-bl-md border border-surface-border bg-slate-900/50 p-3 text-sm text-slate-200 shadow-sm';

              const metaClasses = 'text-xs text-slate-400 mb-1';
              const timeClasses = 'mt-2 text-right text-[11px] text-slate-500';

              return (
                <div key={idx} className={`flex items-end ${isUser ? 'justify-end' : 'justify-start'}`}>
                  {!isUser ? (
                    <div className="mr-3 flex-shrink-0">
                      <div className="h-9 w-9 rounded-full bg-slate-700 flex items-center justify-center text-xs text-slate-200">AI</div>
                    </div>
                  ) : null}

                  <div className={bubbleClasses}>
                    <div className={metaClasses}>{isAssistant ? 'assistant' : m.role}</div>
                    <div className="whitespace-pre-wrap leading-relaxed">
                      <MarkdownRenderer content={m.content} />
                    </div>
                    <div className={timeClasses}>{new Date(m.timestamp).toLocaleString()}</div>
                  </div>

                  {isUser ? (
                    <div className="ml-3 flex-shrink-0">
                      <div className="h-9 w-9 rounded-full bg-cyan-800 flex items-center justify-center text-xs text-slate-100">U</div>
                    </div>
                  ) : null}
                </div>
              );
            })}

            {/* Pending user message (optimistic) */}
            {pendingUserMessage ? (
              <div className={`flex items-end justify-end`}>
                <div className="ml-3 flex-shrink-0">
                  <div className="h-9 w-9 rounded-full bg-cyan-800 flex items-center justify-center text-xs text-slate-100">U</div>
                </div>

                <div className="ml-auto max-w-[65%] rounded-lg rounded-br-md border border-accent-cyan/40 bg-gradient-to-br from-cyan-900/80 to-cyan-800/60 p-3 text-sm text-slate-100 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-slate-400 mb-1">user</div>
                    {pendingUserMessage.error ? (
                      <div className="text-xs text-rose-300 ml-2">Error · Intentos: {pendingUserMessage.attempts ?? 1}</div>
                    ) : null}
                  </div>

                  <div className="whitespace-pre-wrap leading-relaxed">{pendingUserMessage.content}</div>

                  <div className="mt-2 text-right text-[11px] text-slate-500">{new Date(pendingUserMessage.timestamp).toLocaleString()}</div>

                  {pendingUserMessage.error ? (
                    <div className="mt-2 flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => onRetry && onRetry()}
                        disabled={analyzeMutation?.isPending}
                        className="text-xs rounded px-3 py-1 border border-rose-600 bg-rose-900/20 text-rose-300 hover:bg-rose-900/40 disabled:opacity-50"
                      >
                        Reintentar
                      </button>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {/* Placeholder assistant bubble when waiting for response */}
            {analyzeMutation?.isPending ? (
              <div className="flex items-end justify-start">
                <div className="mr-3 flex-shrink-0">
                  <div className="h-9 w-9 rounded-full bg-slate-700 flex items-center justify-center text-xs text-slate-200">AI</div>
                </div>

                <div className="mr-auto max-w-[65%] rounded-lg rounded-bl-md border border-surface-border bg-slate-900/40 p-3 text-sm text-slate-200 shadow-sm animate-pulse">
                  <div className="text-xs text-slate-400 mb-1">assistant</div>
                  <div className="h-4 w-48 rounded bg-slate-800/60" />
                </div>
              </div>
            ) : null}
          </>
        )}
      </div>

      {/* Floating input - sits at bottom of chat area */}
      <form onSubmit={(e) => void handleSubmit(e)} className="absolute left-0 right-0 bottom-1 px-4">
        <div className="mx-auto max-w-full rounded bg-slate-900/30 p-3 backdrop-blur-sm border border-surface-border shadow-lg flex items-start gap-3">
          <select
            disabled={analyzeMutation?.isPending}
            className="w-40 rounded border border-surface-border bg-slate-950/50 p-2 text-xs text-slate-200 focus:outline-none disabled:opacity-50"
            value={selectedModelId}
            onChange={(ev) => setSelectedModelId(ev.target.value)}
          >
            <option value="">Modelo: Default ({defaultModelId})</option>
            {Object.entries(availableModels || {}).map(([id, m]) => (
              <option key={id} value={id}>
                {id} ({m.provider} — {m.model_name})
              </option>
            ))}
          </select>

          <textarea
            disabled={analyzeMutation?.isPending}
            className="flex-1 min-h-[56px] max-h-[160px] resize-none rounded border border-surface-border bg-slate-950/50 p-2 text-sm text-slate-100 disabled:opacity-60"
            placeholder="Escribe aquí tu mensaje forense (ej. 'Revisa intentos de inyección en /api/v1/login')"
            value={query}
            onChange={(ev) => setQuery(ev.target.value)}
          />

          <button
            type="submit"
            className="rounded border border-accent-cyan/60 bg-accent-glow px-4 py-2 text-sm text-cyan-200 disabled:opacity-60"
            disabled={analyzeMutation?.isPending || query.trim().length < 1}
          >
            {analyzeMutation?.isPending ? 'Enviando...' : 'Enviar'}
          </button>
        </div>
      </form>
    </div>
  );
}
