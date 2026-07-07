interface ForensicHighlightsProps {
  highlights: string[];
}

export function ForensicHighlights({ highlights }: ForensicHighlightsProps) {
  if (!highlights || highlights.length === 0) {
    return null;
  }

  return (
    <div className="mb-6 grid grid-cols-1 gap-3 md:grid-cols-3">
      {highlights.map((highlight, index) => {
        // 🕵️‍♂️ Análisis dinámico del texto para asignar colores e iconos automáticos
        const text = highlight.toLowerCase();
        let badgeColor = 'border-slate-800 bg-slate-900/40 text-slate-300';
        let icon = 'ℹ️';
        let category = 'Info';

        if (text.includes('malicious') || text.includes('attack') || text.includes('suspicious')) {
          badgeColor = 'border-red-500/20 bg-red-950/10 text-red-400';
          icon = '🚨';
          category = 'Threat';
        } else if (text.includes('automated') || text.includes('scanning') || text.includes('probing')) {
          badgeColor = 'border-amber-500/20 bg-amber-950/10 text-amber-400';
          icon = '🤖';
          category = 'Activity';
        } else if (text.includes('recommendation') || text.includes('waf') || text.includes('mitigation')) {
          badgeColor = 'border-blue-500/20 bg-blue-950/10 text-blue-400';
          icon = '🛡️';
          category = 'Mitigation';
        }

        return (
          <div
            key={index}
            className={`flex gap-3 rounded-lg border p-3 backdrop-blur-sm transition-all duration-200 hover:bg-slate-900/60 ${badgeColor}`}
          >
            {/* Icono indicador */}
            <div className="mt-0.5 select-none text-sm">{icon}</div>

            {/* Contenido */}
            <div className="flex flex-col gap-0.5">
              <span className="font-mono text-[9px] font-bold uppercase tracking-widest opacity-50">
                {category}
              </span>
              <p className="text-xs font-medium leading-relaxed text-slate-200">{highlight}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
