Plan: SOC Dashboard — Sentinel SOA Frontend v2

TL;DR: Migración completa del frontend actual (CRA + MUI monolítico en App.js) hacia una arquitectura modular con Vite + React 18 + TypeScript + Tailwind CSS + Shadcn/Radix UI + Zustand. El nuevo dashboard expondrá tres vistas tácticas (Dashboard, Alert Center, Log Viewer) consumiendo los endpoints existentes en http://localhost:8000/api/v1/analytics. La migración es in-place: el directorio /frontend se reconstruye desde cero conservando el mismo nginx.conf y Dockerfile.frontend.

 

1. Resumen Ejecutivo

El sistema Sentinel SOA actualmente cuenta con un único archivo App.js (308 líneas) que mezcla lógica de fetching, estado local, y presentación con MUI. No existe tipado, ni separación de concerns, ni routing. El objetivo es construir un SOC Dashboard profesional con:

Arquitectura de features isoladas con contratos TypeScript estrictos.

Un store centralizado Zustand que maneja el estado de alertas (status pending → reviewing → resolved).

Tres vistas funcionales conectadas al backend real vía custom hooks, con mock data para desarrollo offline.

Identidad visual "Cyberpunk Táctico" coherente con la naturaleza del sistema (dark mode, colores neón semánticos, tipografía monoespaciada para datos técnicos).

 

2. Stack Tecnológico con Justificación

Tecnología

Justificación

Vite

Reemplaza react-scripts. HMR instantáneo, build optimizado con tree-shaking. El Dockerfile.frontend usa npm run build — compatible sin cambios en Docker.

React 18 + TypeScript

Concurrent features (Suspense, useTransition) para la tabla virtualizada de logs. TS elimina errores de campo (p.ej. threat_actor.ip_address vs source_ip).

Tailwind CSS v3

Zero-runtime CSS. Diseño utility-first permite iteración rápida de la UI táctica sin hojas de estilo separadas. cn() helper para variantes condicionales.

Shadcn/Radix UI

Primitivos accesibles (ARIA) sin estilos impuestos: Drawer, Dialog, Tooltip, DropdownMenu. Se estilizan con Tailwind.

Zustand

Store mínimo (~2KB). Maneja alertStatuses (map de _id → AlertStatus) y activeFilter sin boilerplate Redux.

Recharts

Ya presente en el proyecto. Familiaridad del equipo + API declarativa JSX + compatibilidad con responsive containers.

Lucide React

Tree-shakeable, coherente con Shadcn, iconos de seguridad: Shield, AlertTriangle, Terminal, Activity.

date-fns

Formateo de created_at_utc (ISO 8601) → timestamps legibles sin Moment.js (peso ~13KB).

React Router v6

Routing declarativo para las tres vistas con layout anidado (sidebar persistente).

TanStack Virtual

Virtualización de filas para el Log Viewer — necesario para tablas de 1000+ entradas de raw_telemetry.

 

3. Arquitectura de Carpetas Completa

/frontend/

├── index.html                        ← Entry point Vite con Google Fonts (JetBrains Mono)

├── vite.config.ts                    ← Proxy /api → http://localhost:8000, path aliases @/

├── tailwind.config.ts                ← Tema "Cyberpunk Táctico" con colores semánticos

├── tsconfig.json                     ← Strict mode, path aliases

├── package.json                      ← Nuevo (reemplaza el actual)

├── nginx.conf                        ← Sin cambios

├── public/

│   └── sentinel-logo.svg

└── src/

    ├── main.tsx                      ← ReactDOM.createRoot, BrowserRouter, QueryClientProvider

    ├── App.tsx                       ← Layout raíz: Sidebar + <Outlet />

    │

    ├── components/                   ← UI atómico reutilizable

    │   ├── ThreatBadge.tsx           ← Badge con color semántico según threat_level

    │   ├── ScoreBar.tsx              ← Barra de progreso con gradiente (reasoning scores)

    │   ├── KpiCard.tsx               ← Card métrica con icono, valor, delta opcional

    │   ├── StatusChip.tsx            ← Chip: pending/reviewing/resolved con colores

    │   ├── IpAddress.tsx             ← <span> con font-mono y copy-to-clipboard

    │   ├── MitreTag.tsx              ← Badge MITRE con link a attack.mitre.org

    │   ├── JsonViewer.tsx            ← Pre-formateado con syntax highlighting básico

    │   ├── TimelineStep.tsx          ← Item de timeline vertical (mitigation steps)

    │   ├── LoadingScreen.tsx         ← Overlay de carga con animación de scanner

    │   ├── ErrorBoundary.tsx         ← React error boundary con fallback UI

    │   └── Sidebar.tsx               ← Nav lateral fijo con links y logo

    │

    ├── features/

    │   ├── dashboard/

    │   │   ├── DashboardPage.tsx     ← Orquesta KPIs + Charts (usa useStats)

    │   │   ├── KpiGrid.tsx           ← Grid 4 columnas de KpiCards

    │   │   ├── AttackTimeline.tsx    ← AreaChart con gradiente (reports por hora)

    │   │   ├── MitreTacticsChart.tsx ← BarChart horizontal (mitre_tactics stats)

    │   │   ├── TopAttackersChart.tsx ← ComposedChart IPs vs response_codes

    │   │   └── ThreatLevelPie.tsx    ← PieChart distribución threat_levels

    │   │

    │   ├── alerts/

    │   │   ├── AlertsPage.tsx        ← Orquesta tabla + drawer (usa useThreats)

    │   │   ├── AlertsTable.tsx       ← Tabla con columnas: level, IP, tactic, score, status

    │   │   ├── AlertsFilters.tsx     ← Filtros: threat_level, status, source_id

    │   │   ├── AlertDrawer.tsx       ← Drawer lateral con detalle completo de amenaza

    │   │   ├── MitigationTimeline.tsx← Timeline 0-5min / 5-30min / 30+min

    │   │   └── ReasoningBreakdown.tsx← Barras de progreso del reasoning_summary

    │   │

    │   └── logs/

    │       ├── LogsPage.tsx          ← Orquesta tabla virtualizada + filtros (usa useLogs)

    │       ├── LogsTable.tsx         ← Tabla virtualizada con TanStack Virtual

    │       ├── LogsFilters.tsx       ← Búsqueda global, método HTTP, status code, IP

    │       └── LogRowExpanded.tsx    ← Fila expandida con JsonViewer del log completo

    │

    ├── hooks/

    │   ├── useThreats.ts             ← fetch /analytics/reports, SWR-like con polling

    │   ├── useStats.ts               ← fetch /analytics/stats, retorna datos para charts

    │   ├── useLogs.ts                ← fetch /analytics/source_ids + raw_telemetry (si existe)

    │   ├── useFilters.ts             ← Estado de filtros activos con URL sync

    │   └── useAlertAction.ts        ← POST /analytics/feedback para cambiar status

    │

    ├── store/

    │   └── sentinelStore.ts          ← Zustand store: alertStatuses, activeSourceId, filters

    │

    ├── types/

    │   ├── threat.ts                 ← Interface Threat, ThreatLevel, AlertStatus, Mitigation

    │   ├── logEntry.ts               ← Interface LogEntry (raw_telemetry)

    │   └── api.ts                    ← Interface StatsResponse, SourceIdsResponse

    │

    ├── data/

    │   ├── mockThreats.ts            ← Array de 10 Threat objects para dev offline

    │   ├── mockLogs.ts               ← Array de 50 LogEntry objects para dev offline

    │   └── mockStats.ts              ← StatsResponse mock para charts

    │

    └── lib/

        ├── cn.ts                     ← clsx + tailwind-merge helper

        ├── formatters.ts             ← formatDate, formatScore, formatBytes

        ├── threatColors.ts           ← Map ThreatLevel → clases Tailwind neón

        └── apiClient.ts             ← fetch wrapper con baseURL, headers, error handling

/frontend/

├── index.html                        ← Entry point Vite con Google Fonts (JetBrains Mono)

├── vite.config.ts                    ← Proxy /api → http://localhost:8000, path aliases @/

├── tailwind.config.ts                ← Tema "Cyberpunk Táctico" con colores semánticos

├── tsconfig.json                     ← Strict mode, path aliases

├── package.json                      ← Nuevo (reemplaza el actual)

├── nginx.conf                        ← Sin cambios

├── public/

│   └── sentinel-logo.svg

└── src/

    ├── main.tsx                      ← ReactDOM.createRoot, BrowserRouter, QueryClientProvider

    ├── App.tsx                       ← Layout raíz: Sidebar + <Outlet />

    │

    ├── components/                   ← UI atómico reutilizable

    │   ├── ThreatBadge.tsx           ← Badge con color semántico según threat_level

    │   ├── ScoreBar.tsx              ← Barra de progreso con gradiente (reasoning scores)

    │   ├── KpiCard.tsx               ← Card métrica con icono, valor, delta opcional

    │   ├── StatusChip.tsx            ← Chip: pending/reviewing/resolved con colores

    │   ├── IpAddress.tsx             ← <span> con font-mono y copy-to-clipboard

    │   ├── MitreTag.tsx              ← Badge MITRE con link a attack.mitre.org

    │   ├── JsonViewer.tsx            ← Pre-formateado con syntax highlighting básico

    │   ├── TimelineStep.tsx          ← Item de timeline vertical (mitigation steps)

    │   ├── LoadingScreen.tsx         ← Overlay de carga con animación de scanner

    │   ├── ErrorBoundary.tsx         ← React error boundary con fallback UI

    │   └── Sidebar.tsx               ← Nav lateral fijo con links y logo

    │

    ├── features/

    │   ├── dashboard/

    │   │   ├── DashboardPage.tsx     ← Orquesta KPIs + Charts (usa useStats)

    │   │   ├── KpiGrid.tsx           ← Grid 4 columnas de KpiCards

    │   │   ├── AttackTimeline.tsx    ← AreaChart con gradiente (reports por hora)

    │   │   ├── MitreTacticsChart.tsx ← BarChart horizontal (mitre_tactics stats)

    │   │   ├── TopAttackersChart.tsx ← ComposedChart IPs vs response_codes

    │   │   └── ThreatLevelPie.tsx    ← PieChart distribución threat_levels

    │   │

    │   ├── alerts/

    │   │   ├── AlertsPage.tsx        ← Orquesta tabla + drawer (usa useThreats)

    │   │   ├── AlertsTable.tsx       ← Tabla con columnas: level, IP, tactic, score, status

    │   │   ├── AlertsFilters.tsx     ← Filtros: threat_level, status, source_id

    │   │   ├── AlertDrawer.tsx       ← Drawer lateral con detalle completo de amenaza

    │   │   ├── MitigationTimeline.tsx← Timeline 0-5min / 5-30min / 30+min

    │   │   └── ReasoningBreakdown.tsx← Barras de progreso del reasoning_summary

    │   │

    │   └── logs/

    │       ├── LogsPage.tsx          ← Orquesta tabla virtualizada + filtros (usa useLogs)

    │       ├── LogsTable.tsx         ← Tabla virtualizada con TanStack Virtual

    │       ├── LogsFilters.tsx       ← Búsqueda global, método HTTP, status code, IP

    │       └── LogRowExpanded.tsx    ← Fila expandida con JsonViewer del log completo

    │

    ├── hooks/

    │   ├── useThreats.ts             ← fetch /analytics/reports, SWR-like con polling

    │   ├── useStats.ts               ← fetch /analytics/stats, retorna datos para charts

    │   ├── useLogs.ts                ← fetch /analytics/source_ids + raw_telemetry (si existe)

    │   ├── useFilters.ts             ← Estado de filtros activos con URL sync

    │   └── useAlertAction.ts        ← POST /analytics/feedback para cambiar status

    │

    ├── store/

    │   └── sentinelStore.ts          ← Zustand store: alertStatuses, activeSourceId, filters

    │

    ├── types/

    │   ├── threat.ts                 ← Interface Threat, ThreatLevel, AlertStatus, Mitigation

    │   ├── logEntry.ts               ← Interface LogEntry (raw_telemetry)

    │   └── api.ts                    ← Interface StatsResponse, SourceIdsResponse

    │

    ├── data/

    │   ├── mockThreats.ts            ← Array de 10 Threat objects para dev offline

    │   ├── mockLogs.ts               ← Array de 50 LogEntry objects para dev offline

    │   └── mockStats.ts              ← StatsResponse mock para charts

    │

    └── lib/

        ├── cn.ts                     ← clsx + tailwind-merge helper

        ├── formatters.ts             ← formatDate, formatScore, formatBytes

        ├── threatColors.ts           ← Map ThreatLevel → clases Tailwind neón

        └── apiClient.ts             ← fetch wrapper con baseURL, headers, error handling

4. Sistema de Tipos TypeScript

src/types/threat.ts

Definir:

ThreatLevel: union type 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

AlertStatus: union type 'pending' | 'reviewing' | 'resolved'

KillChainPhase: union type de las fases MITRE

SuggestedMitigations: interface con immediate: string[], short_term: string[], long_term: string[]

Threat: interface principal con todos los campos del JSON del backend — incluyendo _id, source_ip, threat_level: ThreatLevel, threat_score, kill_chain_phase, mitre_tactic, mitre_tactic_id, mitre_technique, mitre_technique_id, mitre_sub_technique: string | null, mitre_sub_technique_id: string | null, summary, indicators_found: string[], reasoning_summary, suggested_mitigations: SuggestedMitigations, created_at_utc: string, status: AlertStatus, y opcionalmente source_id: string

src/types/logEntry.ts

Definir:

HttpMethod: union type 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'PATCH'

LogEntry: interface mapeada desde LogEvent del backend — _id, source_ip, http_method: HttpMethod, request_uri, response_code, user_agent: string | null, timestamp: string, bytes_sent: number | null, source_id: string

src/types/api.ts

Definir:

ThreatLevelCount: { _id: ThreatLevel; count: number }

KillChainCount: { _id: string; count: number }

AttackerCount: { _id: string; count: number }

StatsResponse: { threat_levels: ThreatLevelCount[]; kill_chain_phases: KillChainCount[]; top_attackers: AttackerCount[]; mitre_tactics?: KillChainCount[] }

FeedbackPayload: { report_id: string; feedback: AlertStatus; analyst_comment?: string }

Notar que stats del backend devuelve threat_actor.ip_address en top_attackers — el tipo debe documentar esta inconsistencia vs source_ip directo en Threat

 

5. Diseño del Zustand Store (src/store/sentinelStore.ts)

Un único store con tres slices lógicos:

State:

activeSourceId: string | null — source_id seleccionado globalmente (era el selector de la AppBar en el App.js original)

sourceIds: string[] — lista cargada al init desde /analytics/source_ids

alertStatuses: Record<string, AlertStatus> — map de _id → status para overrides optimistas locales

alertHistory: Record<string, string[]> — map de _id → comentarios del analista

selectedThreatId: string | null — ID de la amenaza cuyo Drawer está abierto

filters: objeto con { threatLevel: ThreatLevel | null; status: AlertStatus | null; searchQuery: string }

Actions:

setActiveSourceId(id: string) — cambia source, resetea filters

setSourceIds(ids: string[]) — inicialización

setAlertStatus(id: string, status: AlertStatus) — mutación optimista + llama a useAlertAction

selectThreat(id: string | null) — abre/cierra Drawer

setFilter(key, value) — actualiza filtro específico

resetFilters() — limpia todos los filtros

 

6. Configuración de Tailwind CSS (tailwind.config.ts)

Extender theme.extend con:

Colores semánticos:

threat-critical: '#ef4444' (red-500 neón)

threat-high: '#f97316' (orange-500)

threat-medium: '#eab308' (yellow-500)

threat-low: '#3b82f6' (blue-500)

surface-base: '#020617' (slate-950 — fondo principal)

surface-elevated: '#0f172a' (slate-900 — cards)

surface-border: '#1e293b' (slate-800 — bordes)

accent-cyan: '#06b6d4' (cyan-500 — accents interactivos)

accent-glow: 'rgba(6, 182, 212, 0.15)' — glow sutil en hover

Familia de fuentes:

font-mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace'] — para IPs, hashes, URIs

font-sans: ['Inter', 'system-ui'] — para texto general

Animaciones personalizadas:

animate-pulse-slow: pulse de 3s para indicadores de alerta activa

animate-scan: barrido horizontal para loading screen (clip-path)

animate-fade-in: opacity 0→1, translateY 4px→0, duration 200ms

Plugins: @tailwindcss/forms para estilizar inputs nativos, tailwindcss-animate para transiciones de Shadcn

 

7. Detalle de Componentes Clave con Props

ThreatBadge

Props: level: ThreatLevel; size?: 'sm' | 'md' Renderiza un <span> con bg-threat-{level}/10 text-threat-{level} border border-threat-{level}/30. Usa threatColors.ts para el mapeo.

KpiCard

Props: title: string; value: string | number; subtitle?: string; icon: LucideIcon; trend?: { delta: number; label: string }; accentColor?: string Card con fondo surface-elevated, borde semitransparente, icono con color accent. Si trend existe, muestra flecha up/down con color semántico.

ScoreBar

Props: label: string; score: number; maxScore?: number; color?: string Barra de progreso animada al montar (width 0 → score%). Background con gradiente threat-color. Muestra label a la izquierda y valor numérico a la derecha.

AlertDrawer

Props: threat: Threat | null; isOpen: boolean; onClose: () => void; onStatusChange: (id: string, status: AlertStatus) => void Radix UI Sheet desde el lado derecho, ancho w-[560px]. Secciones internas: Header con ThreatBadge + score, MITRE section con MitreTags, ReasoningBreakdown, MitigationTimeline, footer con botones de acción.

MitigationTimeline

Props: mitigations: SuggestedMitigations Tres TimelineStep agrupados: immediate (⚡ 0-5 min, rojo), short_term (🔧 5-30 min, naranja), long_term (🛡️ 30+ min, azul). Línea vertical conectora entre steps.

LogsTable

Props: logs: LogEntry[]; onRowExpand: (id: string) => void TanStack Virtual con overscan: 10. Columnas: timestamp, source_ip (IpAddress), method (badge de color), request_uri (truncado con Tooltip), response_code (coloreado 2xx=verde, 4xx=naranja, 5xx=rojo), bytes_sent. Row expandible con JsonViewer.

AttackTimeline (Chart)

Props: data: { timestamp: string; count: number; criticalCount: number }[] AreaChart de Recharts. data se computa en useStats agrupando reports por hora con date-fns/startOfHour. Dos áreas: total (cyan con gradiente) y critical (rojo, opacidad 60%).

 

8. Custom Hooks

useThreats(sourceId: string | null)

Fetching de /api/v1/analytics/reports?source_id={sourceId}. Polling cada 30s con setInterval. Retorna { threats: Threat[]; loading: boolean; error: Error | null; refetch: () => void }. Aplica overrides del store Zustand sobre el status del backend antes de retornar.

useStats(sourceId: string | null)

Fetching de /api/v1/analytics/stats?source_id={sourceId}. Retorna { stats: StatsResponse | null; loading: boolean }. Deriva timelineData agrupando reports por hora (requiere useThreats como dependencia o fetch conjunto).

useLogs(sourceId: string | null)

Fetching de /api/v1/analytics/reports filtrado por source_id para logs crudos (hasta que se exponga raw_telemetry directamente). Preparado con TODO comment para migrar a /analytics/raw_logs endpoint futuro. Retorna paginación virtual (slice del array por page * pageSize).

useFilters()

Lee/escribe filters del store Zustand. Retorna función applyFilters(threats: Threat[]): Threat[] que aplica todos los filtros activos. Sincroniza searchQuery con URLSearchParams via useSearchParams.

useAlertAction()

Retorna función submitFeedback(reportId: string, status: AlertStatus, comment?: string): Promise<void> que hace POST a /api/v1/analytics/feedback. Antes de la llamada, actualiza optimistamente el store. En error, revierte.

 

9. Estrategia de Conexión con el Backend

src/lib/apiClient.ts

Wrapper sobre fetch nativo con:

baseURL: leer de import.meta.env.VITE_API_BASE_URL (default: http://localhost:8000)

Función genérica apiFetch<T>(path, options?): Promise<T> con manejo centralizado de errores HTTP

Header Content-Type: application/json automático en POST

vite.config.ts — Proxy de desarrollo

Configurar server.proxy para /api → http://localhost:8000. Esto evita CORS en dev y permite que los imports usen paths relativos. En producción, el nginx.conf existente gestiona el proxy.

Mapeo de endpoints existentes a hooks:



GET  /api/v1/analytics/source_ids        → inicialización del store (sentinelStore.setSourceIds)

GET  /api/v1/analytics/reports           → useThreats

GET  /api/v1/analytics/stats             → useStats

POST /api/v1/analytics/feedback          → useAlertAction

GET  /api/v1/analytics/debug_reports     → solo en entorno development (DevTools panel)



Nota sobre raw_telemetry:

El endpoint de logs raw aún no está expuesto en analytics.py. El Log Viewer usará los analysis_reports con campos de LogEvent en un primer MVP, con un TODO claro para migrar cuando se agregue /api/v1/analytics/logs al router.

.env y .env.example:



VITE_API_BASE_URL=http://localhost:8000

VITE_POLLING_INTERVAL_MS=30000

VITE_MOCK_DATA=false



10. Plan de Implementación por Fases

Phase 1: Setup & Scaffolding (Día 1-2)

Crear el nuevo proyecto Vite+TypeScript dentro de /frontend (backup del App.js original en /frontend/src/App.legacy.js).

Instalar todas las dependencias (ver sección 11).

Configurar tailwind.config.ts con el tema completo.

Configurar tsconfig.json con strict mode y path alias @/ → ./src.

Configurar vite.config.ts con proxy y alias.

Crear estructura de carpetas completa con archivos index.ts barrel.

Crear todos los tipos en /types/.

Crear src/lib/cn.ts, formatters.ts, threatColors.ts, apiClient.ts.

Poblar /data/ con mock data alineada a las interfaces TypeScript.

Phase 2: Layout & Navigation (Día 3)

Implementar Sidebar.tsx con React Router NavLink — links a /, /alerts, /logs. Indicador de source_id activo. Logo Sentinel en header.

Implementar App.tsx como layout raíz: flex h-screen bg-surface-base. Sidebar fijo 240px + <Outlet /> en área principal con scroll.

Configurar rutas en main.tsx: / → DashboardPage, /alerts → AlertsPage, /logs → LogsPage.

Inicializar store: fetch de source_ids en App mount, setear primer sourceId como activo (replicando lógica del App.js original).

Implementar LoadingScreen y ErrorBoundary.

Phase 3: Features (Día 4-8)

Dashboard (Día 4):

Implementar useStats + useThreats.

Implementar KpiGrid con 4 KpiCard: Total Amenazas (Shield), Alertas Críticas Activas (AlertTriangle), Avg Threat Score (Activity), Top Attacker IP (Zap).

Implementar AttackTimeline, MitreTacticsChart, ThreatLevelPie, TopAttackersChart con Recharts.

Alert Center (Día 5-6):

Implementar AlertsFilters con Radix Select para level/status y source_id.

Implementar AlertsTable con columnas ordenables.

Implementar AlertDrawer con todas las sub-secciones: ReasoningBreakdown, MitigationTimeline, MitreTag.

Conectar useAlertAction al botón "Ejecutar Bloqueo de IP".

Implementar transición optimista de status en el store.

Log Viewer (Día 7-8):

Implementar useLogs con paginación.

Implementar LogsFilters con búsqueda global (debounce 300ms), Select de método HTTP, Select de status code range.

Implementar LogsTable con TanStack Virtual.

Implementar LogRowExpanded con JsonViewer.

Phase 4: Polish & Optimization (Día 9-10)

Añadir micro-interacciones: hover states en rows (translateX 2px), transición de Drawer (animate-in slide-in-from-right), KpiCard con hover:border-accent-cyan/50.

Implementar useTransition de React 18 para las actualizaciones de filtros (mantiene UI responsiva durante re-renders pesados).

Auditoría de accesibilidad: todos los botones con aria-label, tablas con role="grid", Drawer con aria-labelledby.

Optimizar bundle: React.lazy() + Suspense para cada feature page (code splitting por ruta).

Añadir manejo de estado vacío (EmptyState) y skeleton loaders para KpiCards y tabla.

Verificar que nginx.conf y Dockerfile.frontend siguen funcionando con npm run build → /app/dist.



11. Comandos de Instalación

# Desde /frontend — borrar node_modules y package.json actuales

cd frontend



# 1. Crear proyecto Vite (seleccionar React + TypeScript)

npm create vite@latest . -- --template react-ts



# 2. Dependencias de producción

npm install \

  react-router-dom \

  recharts \

  zustand \

  date-fns \

  lucide-react \

  clsx \

  tailwind-merge \

  @radix-ui/react-dialog \

  @radix-ui/react-sheet \

  @radix-ui/react-tooltip \

  @radix-ui/react-select \

  @radix-ui/react-dropdown-menu \

  @radix-ui/react-progress \

  @tanstack/react-virtual



# 3. Dependencias de desarrollo

npm install -D \

  tailwindcss \

  postcss \

  autoprefixer \

  @tailwindcss/forms \

  tailwindcss-animate \

  @types/react \

  @types/react-dom



# 4. Inicializar Tailwind

npx tailwindcss init -p --ts



# 5. Fuentes (añadir en index.html)

# <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">



12. Consideraciones de Performance y Accesibilidad

Performance:

React.lazy + Suspense por ruta: el bundle inicial solo carga el Dashboard.

useTransition para actualizaciones de filtros en AlertsTable con 100+ rows.

TanStack Virtual renderiza solo ~15 filas visibles de los logs (DOM mínimo).

Recharts: usar isAnimationActive={false} en producción si los charts se re-renderizan frecuentemente por polling.

Polling inteligente: pausar setInterval cuando la pestaña no está visible (document.visibilityState).

Accesibilidad:

Todos los Radix UI primitivos son ARIA-compliant por defecto.

ThreatBadge incluye aria-label="Threat level: CRITICAL" — no depender solo del color.

IpAddress tiene title attribute y botón de copy con aria-label="Copy IP address".

Navegación por teclado: Tab entre KpiCards, Enter para abrir Drawer, Escape para cerrar.

Contraste: verificar que text-threat-medium (amarillo) sobre surface-elevated (slate-900) cumple WCAG AA (ratio ≥ 4.5:1). Ajustar lightness si es necesario.

 

13. Checklist de Implementación

PHASE 1 — SETUP

[ ] Backup App.js → App.legacy.js

[ ] Proyecto Vite inicializado y corriendo en dev

[ ] tailwind.config.ts con tema completo

[ ] tsconfig.json con strict + path aliases

[ ] vite.config.ts con proxy /api

[ ] /types/ completo y sin errores TS

[ ] /lib/ completo (cn, formatters, threatColors, apiClient)

[ ] /data/ con mock data tipada



PHASE 2 — LAYOUT

[ ] Sidebar con NavLink activos

[ ] App.tsx con layout flex + Outlet

[ ] Rutas configuradas (/, /alerts, /logs)

[ ] Source IDs cargados al init en store

[ ] LoadingScreen y ErrorBoundary operativos



PHASE 3 — FEATURES DASHBOARD

[ ] useStats conectado a /analytics/stats

[ ] useThreats conectado a /analytics/reports

[ ] KpiGrid con 4 KpiCards con datos reales

[ ] AttackTimeline chart funcional

[ ] MitreTacticsChart funcional

[ ] ThreatLevelPie funcional

[ ] TopAttackersChart funcional



PHASE 3 — FEATURES ALERTS

[ ] AlertsTable con datos reales

[ ] AlertsFilters operativos con URL sync

[ ] AlertDrawer abre con threat seleccionado

[ ] ReasoningBreakdown con ScoreBars

[ ] MitigationTimeline con tres fases

[ ] MitreTag con links a attack.mitre.org

[ ] Botón "Ejecutar Bloqueo" → POST /feedback + update store



PHASE 3 — FEATURES LOGS

[ ] LogsTable virtualizada con TanStack Virtual

[ ] LogsFilters con debounce de búsqueda

[ ] LogRowExpanded con JsonViewer

[ ] useLogs con paginación



PHASE 4 — POLISH

[ ] React.lazy code splitting por ruta

[ ] Skeleton loaders en KpiCards y tabla

[ ] EmptyState components

[ ] Micro-interacciones y transiciones

[ ] useTransition en filtros

[ ] Pausa polling en tab inactiva

[ ] Auditoría ARIA labels

[ ] Verificación contraste WCAG AA

[ ] Dockerfile.frontend build exitoso con nueva estructura

[ ] nginx.conf sirve /dist correctamente



Consideraciones Finales

Discrepancia de campo source_ip vs threat_actor.ip_address: En analytics.py, top_attackers agrega por threat_actor.ip_address, pero el JSON de amenaza tiene source_ip directo. Verificar con el equipo backend qué campo usa analysis_reports realmente (el debug_reports endpoint es útil para esto). El tipo Threat debe tener ambos como opcionales inicialmente.

Endpoint de logs raw: raw_telemetry collection existe en MongoDB pero no tiene endpoint REST. Opciones: A) Usar analysis_reports como proxy para el Log Viewer (MVP) / B) Solicitar al equipo backend que agregue GET /api/v1/analytics/logs con los mismos filtros / C) Implementar el endpoint en analytics.py como parte de esta fase.

mitre_tactics en StatsResponse: El $facet actual en analytics.py no incluye mitre_tactics en la agregación — solo threat_levels, kill_chain_phases, y top_attackers. El MitreTacticsChart necesita que se agregue {"$group": {"_id": "$mitre_tactic", "count": {"$sum": 1}}} al pipeline, o alternativamente derivar los datos desde el array de reports en el frontend. 

