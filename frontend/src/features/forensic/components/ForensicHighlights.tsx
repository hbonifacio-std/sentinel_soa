import React from 'react';

interface ForensicHighlightsProps {
  highlights: string[];
}

const IconGlobe = () => (
  <svg className="h-4 w-4 text-slate-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M12 2a10 10 0 100 20 10 10 0 000-20z" stroke="#94a3b8" strokeWidth="1.2" strokeOpacity="0.9" fill="none" />
    <path d="M2 12h20M12 2c2.5 3 2.5 9 0 14M12 2c-2.5 3-2.5 9 0 14" stroke="#94a3b8" strokeWidth="0.9" strokeOpacity="0.7" />
  </svg>
);

const IconLink = () => (
  <svg className="h-4 w-4 text-slate-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M10.59 13.41a5 5 0 007.07 0l1.41-1.41a5 5 0 00-7.07-7.07L8.59 6.34" stroke="#94a3b8" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M13.41 10.59a5 5 0 00-7.07 0L4.93 12a5 5 0 007.07 7.07L13.41 17" stroke="#94a3b8" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const IconTool = () => (
  <svg className="h-4 w-4 text-slate-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M21 7l-9 9-4 1 1-4 9-9" stroke="#94a3b8" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M7 7l4 4" stroke="#94a3b8" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const IconWarning = () => (
  <svg className="h-4 w-4 text-amber-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94A2 2 0 0021 18L12.71 3.86a2 2 0 00-3.42 0z" stroke="#f59e0b" strokeWidth="1" fill="none" />
    <path d="M12 9v4M12 17h.01" stroke="#f59e0b" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const IconTag = () => (
  <svg className="h-4 w-4 text-slate-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M20 10v6a2 2 0 01-2 2h-6L4 10V4a2 2 0 012-2h6l8 8z" stroke="#94a3b8" strokeWidth="1" fill="none" />
    <path d="M7 7h.01" stroke="#94a3b8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const IconSource = () => (
  <svg className="h-4 w-4 text-slate-300" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="#94a3b8" strokeWidth="1" fill="none" />
    <path d="M14 2v6h6" stroke="#94a3b8" strokeWidth="1" fill="none" />
  </svg>
);

// Compact chip-style highlights: small cards like reference image with SVG icons
export function ForensicHighlights({ highlights }: ForensicHighlightsProps) {
  if (!highlights || highlights.length === 0) return null;

  const ips = new Set<string>();
  const routes = new Set<string>();
  const tools = new Set<string>();
  const httpCodes = new Set<string>();
  const attacks = new Set<string>();
  const sources = new Set<string>();
  let severityTop: string | undefined;

  // Regexes for extraction when CSV format differs
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const routeRegex = /\b\/[^\s,;|)\]]+/g;
  const toolRegex = /\b[a-zA-Z0-9_\-]+\/[0-9.\-]+\b/g; // e.g. python-requests/2.28.1
  const httpRegex = /HTTP\s*(\d{3})/ig;
  const severityRegex = /\b(critical|high|medium|low)\b/i;

  for (const h of highlights) {
    const parts = h.split(',').map((p) => p.trim());
    // try CSV: SEVERITY,SOURCE,ATTACK,TOOL,IP,ROUTE
    const [sev, source, attack, tool, ip, route] = parts;
    if (sev && /\w/.test(sev)) {
      const s = sev.toLowerCase();
      if (!severityTop || s === 'critical' || (s === 'high' && severityTop !== 'critical')) severityTop = sev;
    }
    if (attack) attacks.add(attack);
    if (tool) tools.add(tool);
    if (source) sources.add(source);
    if (ip) ip.split(/;|\||,/).map((x) => x.trim()).forEach((x) => x && ips.add(x));
    if (route) route.split(/;|\||,/).map((x) => x.trim()).forEach((x) => x && routes.add(x));

    // fallback: extract IPs, routes, tools, http codes from raw string
    const raw = h;
    const ipMatches = raw.match(ipRegex);
    if (ipMatches) ipMatches.forEach((m) => ips.add(m));

    const routeMatches = raw.match(routeRegex);
    if (routeMatches) routeMatches.forEach((r) => routes.add(r));

    const toolMatches = raw.match(toolRegex);
    if (toolMatches) toolMatches.forEach((t) => tools.add(t));

    let m: RegExpExecArray | null;
    while ((m = httpRegex.exec(raw)) !== null) {
      if (m[1]) httpCodes.add(m[1]);
    }

    const sevMatch = raw.match(severityRegex);
    if (sevMatch && sevMatch[1]) {
      const s = sevMatch[1];
      if (!severityTop || s.toLowerCase() === 'critical' || (s.toLowerCase() === 'high' && severityTop !== 'critical')) severityTop = s;
    }

    // also try to extract a 'source:' pattern e.g. 'SOURCE=acme-corp' or 'source: acme'
    const sourceMatch = raw.match(/source\s*[:=]\s*([^,;|\n]+)/i);
    if (sourceMatch && sourceMatch[1]) sources.add(sourceMatch[1].trim());

    // detect common attack keywords
    const lower = raw.toLowerCase();
    if (lower.includes('sql') || lower.includes('injection')) attacks.add('SQL Injection');
    if (lower.includes('enumeration')) attacks.add('Enumeration');
    if (lower.includes('brute') || lower.includes('credential')) attacks.add('Brute force');
  }

  // If no extracted items, try fallback: show raw tokens
  const empty = ips.size === 0 && routes.size === 0 && tools.size === 0 && httpCodes.size === 0 && attacks.size === 0;
  if (empty) {
    highlights.forEach((h, i) => {
      // split by common separators and add as generic tool/attack
      h.split(/[,|;]+/).map((p) => p.trim()).filter(Boolean).forEach((token) => {
        if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(token)) ips.add(token);
        else if (/^\//.test(token)) routes.add(token);
        else if (/\d/.test(token) && token.length <= 4) httpCodes.add(token);
        else attacks.add(token);
      });
    });
  }

  const ACCENT = {
    chipBg: 'bg-cyan-900/30',
    chipBorder: 'border-cyan-700',
    chipText: 'text-cyan-100',
    badge: 'bg-cyan-800 text-cyan-100',
  } as const;

  const variantStyles: Record<string, string> = {
    ip: 'bg-cyan-900/30 border-cyan-700 text-cyan-100',
    route: 'bg-teal-900/25 border-teal-700 text-teal-100',
    tool: 'bg-amber-900/25 border-amber-700 text-amber-100',
    attack: 'bg-violet-900/25 border-violet-700 text-violet-100',
    source: 'bg-indigo-900/25 border-indigo-700 text-indigo-100',
    http: 'bg-pink-900/25 border-pink-700 text-pink-100',
    default: 'bg-slate-800/40 border-surface-border text-slate-200',
  };

  const chip = (icon: React.ReactNode, value: string, variant: string = 'default', key?: string) => (
    <span
      key={key || value}
      className={`inline-flex items-center gap-2 rounded-full border px-2 py-1 text-[11px] ${variantStyles[variant] || variantStyles.default}`}
      title={value}
    >
      <span className="flex-shrink-0">{icon}</span>
      <span className="truncate">{value}</span>
    </span>
  );

  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Highlighted indicators & IOCs</h4>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            {severityTop ? (
              <span
                className={`text-xs font-semibold rounded px-2 py-1 ${(() => {
                  const s = ( severityTop || '').toLowerCase();
                  if (s.includes('critical')) return 'bg-red-800 text-red-100';
                  if (s.includes('high')) return 'bg-rose-700 text-rose-100';
                  if (s.includes('medium')) return 'bg-amber-700 text-amber-100';
                  if (s.includes('low')) return 'bg-emerald-700 text-emerald-100';
                  return ACCENT.badge;
                })()}`}
              >
               SEVERITY {severityTop.toUpperCase()}
              </span>
            ) : (
              <span className="text-xs text-slate-500">—</span>
            )}
          </div>

          <div className="ml-2 flex items-center gap-2">
            {Array.from(sources).slice(0, 3).map((s) => chip(<IconSource />, s, 'source'))}
          </div>
        </div>
      </div>

      <div className="rounded-md border border-surface-border bg-slate-900/40 p-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* Attacker IPs */}
          {Array.from(ips).map((ip) => chip(<IconGlobe />, ip, 'ip'))}

          {/* Routes */}
          {Array.from(routes).map((r) => (
            <span
              key={r}
              className={`inline-flex items-center gap-2 rounded-full border px-2 py-1 text-[11px] ${variantStyles.route}`}
              title={r}
            >
              <span className="flex-shrink-0"><IconLink /></span>
              <code className="font-mono text-[11px] truncate">{r}</code>
            </span>
          ))}

          {/* Tools */}
          {Array.from(tools).map((t) => chip(<IconTool />, t, 'tool'))}

          {/* HTTP codes */}
          {Array.from(httpCodes).map((c) => chip(<IconWarning />, `HTTP ${c}`, 'http'))}

          {/* Attacks (small tags) */}
          {Array.from(attacks).map((a) => (
            <span key={a} className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] ${variantStyles.attack}`}>
              <span className="inline-flex items-center gap-1"><IconTag /> <span>{a}</span></span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
