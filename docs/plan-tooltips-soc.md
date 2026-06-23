# Plan: Enrich Recharts Custom Tooltips in SOC Dashboard

> **Objetivo:** Reemplazar los `<Tooltip />` por defecto de Recharts en los tres gráficos del dashboard por tooltips contextuales con valor operativo para el analista de SOC.  
> **Stack:** React 18 · TypeScript · Recharts 2.15.4 · Tailwind CSS · date-fns 4  
> **Paquetes nuevos requeridos:** ❌ Ninguno

---

## Estado actual

| Archivo | Tipo de gráfico | Tooltip actual | Datos que recibe |
|---|---|---|---|
| `AttackTimeline.tsx` | AreaChart | `<Tooltip />` default | `{ timestamp, count, criticalCount }` |
| `MitreTacticsChart.tsx` | BarChart horizontal | `<Tooltip />` default | `{ _id, count }` |
| `ThreatLevelPie.tsx` | PieChart | `<Tooltip />` default | `{ _id, count }` |

**Problema central:** los datos que llegan a los gráficos son demasiado planos. Antes de crear los tooltips se deben enriquecer las interfaces y los hooks que producen los datos.

---

## Checklist de implementación

### Fase 1 — Enriquecer tipos en `types/api.ts`

- [ ] **1.1** Añadir interfaz `TechniqueRef`:

  ```ts
  export interface TechniqueRef {
    name: string;
    id: string;
  }
  ```

- [ ] **1.2** Añadir interfaz `MitreTacticRow` (reemplaza el uso de `KillChainCount` en los gráficos MITRE):

  ```ts
  export interface MitreTacticRow {
    _id: string;           // nombre de la táctica, ej. "Initial Access"
    tacticId?: string;     // ej. "TA0001"
    count: number;
    techniques: TechniqueRef[];  // lista deduplicada de técnicas detectadas
    topPaths: string[];          // hasta 3 request_uri más frecuentes
  }
  ```

- [ ] **1.3** Añadir interfaz `TimelineRow` (extraerla de `AttackTimeline.tsx` y enriquecerla):

  ```ts
  export interface TimelineRow {
    timestamp: string;
    count: number;
    criticalCount: number;
    dominantIp: string | null;
    dominantUserAgent: string | null;    // ver nota en Fase 2
    dominantResponseCode: number | null; // ver nota en Fase 2
  }
  ```

- [ ] **1.4** Añadir interfaz `ThreatLevelRow` (reemplaza `ThreatLevelCount` en el Pie):

  ```ts
  export interface ThreatLevelRow {
    _id: string;            // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    count: number;          // total
    activeCount: number;    // resolved === false
    mitigatedCount: number; // resolved === true
  }
  ```

---

### Fase 2 — Cambios en `hooks/useStats.ts`

- [ ] **2.1** Actualizar `timelineData` (`useMemo`) para producir `TimelineRow[]`:
  - Por cada bucket horario, acumular un `Map<string, number>` de frecuencias de `source_ip`.
  - Al cerrar el bucket, elegir la IP con mayor frecuencia como `dominantIp`.
  - **`dominantUserAgent` y `dominantResponseCode`** — `Threat` no contiene estos campos (pertenecen a `LogEntry`). Elegir una opción:
    - **Opción A (recomendada):** Recibir `logs: LogEntry[]` como segundo parámetro de `useStats` y hacer un join por `source_ip` dentro del mismo rango horario.
    - **Opción B (simple):** Poner ambos campos en `null` y omitir esas filas en el tooltip si no hay datos. No requiere cambios de firma.

- [ ] **2.2** Actualizar `mitreTactics` (`useMemo`) para producir `MitreTacticRow[]` (ruta derivada, cuando no hay datos del API):
  - Agrupar threats por `mitre_tactic`.
  - Por grupo: recopilar pares `{ name: mitre_technique, id: mitre_technique_id }` únicos (descartar nulls) → `techniques[]`.
  - Por grupo: recopilar `request_uri` desde `details?.request_uri` (o logs, si Opción A), calcular frecuencias y tomar top 3 → `topPaths[]`.
  - Asignar `tacticId` del primer threat con `mitre_tactic_id` no nulo del grupo.

- [ ] **2.3** Ruta API (cuando `stats?.mitre_tactics` viene del backend — es `KillChainCount[]`): mapear a `MitreTacticRow` con `techniques: []` y `topPaths: []` como degradación controlada.

- [ ] **2.4** Añadir `threatLevelData` como nuevo `useMemo`:

  ```ts
  const threatLevelData = useMemo((): ThreatLevelRow[] => {
    const map = new Map<string, { count: number; activeCount: number; mitigatedCount: number }>();
    threats.forEach((t) => {
      const entry = map.get(t.threat_level) ?? { count: 0, activeCount: 0, mitigatedCount: 0 };
      entry.count += 1;
      if (t.resolved === false) entry.activeCount += 1;
      if (t.resolved === true)  entry.mitigatedCount += 1;
      map.set(t.threat_level, entry);
    });
    return Array.from(map.entries()).map(([_id, v]) => ({ _id, ...v }));
  }, [threats]);
  ```

- [ ] **2.5** Exportar `threatLevelData` en el retorno del hook.

---

### Fase 3 — Actualizar `DashboardPage.tsx`

- [ ] **3.1** Destructurar `threatLevelData` desde `useStats`.
- [ ] **3.2** Pasar `data={threatLevelData}` a `<ThreatLevelPie>` en lugar de `data={stats?.threat_levels ?? []}`.

---

### Fase 4 — Componente compartido `TooltipShell`

- [ ] **4.1** Crear `frontend/src/components/TooltipShell.tsx`:

  ```tsx
  interface TooltipShellProps {
    accentColor: string;
    children: React.ReactNode;
  }

  export function TooltipShell({ accentColor, children }: TooltipShellProps) {
    return (
      <div style={{
        background: '#111c3a',
        border: `1px solid ${accentColor}`,
        boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
        borderRadius: '8px',
        padding: '12px 16px',
        minWidth: '210px',
        fontSize: '12px',
        color: '#e2e8f0',
        pointerEvents: 'none',
      }}>
        {children}
      </div>
    );
  }
  ```

- [ ] **4.2** Exportar también `TooltipRow` desde el mismo archivo — helper para filas label/valor:

  ```tsx
  export function TooltipRow({
    label, value, color = '#e2e8f0',
  }: { label: string; value: React.ReactNode; color?: string }) {
    return (
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', marginTop: '4px' }}>
        <span style={{ color: '#94a3b8' }}>{label}</span>
        <span style={{ color, fontWeight: 600 }}>{value}</span>
      </div>
    );
  }
  ```

- [ ] **4.3** Exportar `TooltipDivider` — separador visual:

  ```tsx
  export function TooltipDivider() {
    return <hr style={{ borderColor: '#1e3a5f', margin: '8px 0' }} />;
  }
  ```

---

### Fase 5 — `TimelineTooltip` (dentro de `AttackTimeline.tsx`)

- [ ] **5.1** Importar `TooltipProps` de `recharts`, `format` y `parseISO` de `date-fns`.
- [ ] **5.2** Importar `TimelineRow` desde `types/api.ts`. Eliminar la interfaz local.
- [ ] **5.3** Crear `TimelineTooltip` con firma `(props: TooltipProps<number, string>)`:
  - Guard: `if (!active || !payload?.length) return null`.
  - Extraer `row = payload[0].payload as TimelineRow`.
  - Formatear timestamp: `format(parseISO(row.timestamp), "d MMM yyyy · HH:mm 'UTC'")`.

- [ ] **5.4** Estructura visual del tooltip:

  ```
  ┌─────────────────────────────────────────┐
  │  19 Jun 2026 · 19:00 UTC          14px  │
  ├─────────────────────────────────────────┤
  │  Total alertas          12        cyan  │
  │  Críticas                3        red   │
  │  Otras                   9        yellow│
  ├─────────────────────────────────────────┤
  │  IP Principal      10.10.20.5     muted │
  │  User-Agent        sqlmap/1.7.8…  muted │
  │  HTTP dominante    401             red  │
  └─────────────────────────────────────────┘
  ```

  - Colores: total = `#06b6d4`, críticas = `#ef4444`, otras = `#eab308`.
  - HTTP code: verde (`#22c55e`) si `< 400`, rojo (`#ef4444`) si `>= 400`.
  - User-Agent: truncar a 28 chars + `…`.
  - Si `dominantIp` o `dominantResponseCode` son `null`, mostrar `'—'`.

- [ ] **5.5** Pasar a `<Tooltip content={<TimelineTooltip />} cursor={{ stroke: '#06b6d4', strokeWidth: 1, strokeDasharray: '4 4' }} />`.

---

### Fase 6 — `MitreTacticTooltip` (dentro de `MitreTacticsChart.tsx`)

- [ ] **6.1** Importar `MitreTacticRow` desde `types/api.ts`. Eliminar la interfaz local `Row`.
- [ ] **6.2** Crear `MitreTacticTooltip`:
  - Guard igual al anterior.
  - Extraer `row = payload[0].payload as MitreTacticRow`.

- [ ] **6.3** Estructura visual:

  ```
  ┌─────────────────────────────────────────┐
  │  Initial Access  [TA0001]         14px  │
  ├─────────────────────────────────────────┤
  │  Eventos                 7       orange │
  ├─────────────────────────────────────────┤
  │  Técnicas detectadas:                   │
  │  · Exploit Public-Facing (T1190)        │
  │  · Valid Accounts         (T1078)       │
  ├─────────────────────────────────────────┤
  │  Paths más atacados:                    │
  │  /auth/login                            │
  │  /admin/upload                          │
  └─────────────────────────────────────────┘
  ```

  - Insignia `tacticId`: `background: #1e3a5f`, `color: #f97316`, `borderRadius: 4px`, `padding: 1px 6px`, `fontSize: 11px`.
  - Técnicas: máximo 4; si hay más, mostrar `+{n} más`.
  - Paths: máximo 3, truncados a 32 chars. Omitir sección si `topPaths` está vacío.

- [ ] **6.4** Pasar `<Tooltip content={<MitreTacticTooltip />} cursor={{ fill: '#f9731611' }} />`.

---

### Fase 7 — `ThreatLevelTooltip` (dentro de `ThreatLevelPie.tsx`)

- [ ] **7.1** Importar `ThreatLevelRow` desde `types/api.ts`. Eliminar interfaz local `Row`.
- [ ] **7.2** Definir `LEVEL_META` lookup:

  ```ts
  const LEVEL_META: Record<string, { color: string; emoji: string }> = {
    CRITICAL: { color: '#ef4444', emoji: '🔴' },
    HIGH:     { color: '#f97316', emoji: '🟠' },
    MEDIUM:   { color: '#eab308', emoji: '🟡' },
    LOW:      { color: '#3b82f6', emoji: '🔵' },
  };
  ```

- [ ] **7.3** Estructura visual:

  ```
  ┌─────────────────────────────────────────┐
  │  🔴 CRITICAL                      14px  │
  ├─────────────────────────────────────────┤
  │  Total alertas           8        white │
  │  Activas 🔥              5        red   │
  │  Mitigadas ✓             3        green │
  ├─────────────────────────────────────────┤
  │  [████████████░░░░░░░░░]  barra % rojo  │
  └─────────────────────────────────────────┘
  ```

  - Barra de progreso (opcional): dos segmentos inline (`activeCount/count` en rojo, `mitigatedCount/count` en verde), fondo `#1e3a5f`, altura `6px`, `borderRadius: 3px`.
  - Borde del `TooltipShell` = `meta.color` del nivel.

- [ ] **7.4** Pasar `<Tooltip content={<ThreatLevelTooltip />} />` (Pie no usa `cursor`).

---

### Fase 8 — Actualizar mock data

- [ ] **8.1** En `mockThreats.ts`: corregir errores de tipo actuales:
  - `reasoning_summary` debe ser `string`, no objeto.
  - `suggested_mitigations` debe ser `SuggestedMitigationItem[]`, no objeto con claves.

- [ ] **8.2** Añadir un segundo mock con `threat_level: 'CRITICAL'`, `resolved: true`, timestamps desfasados +2 horas para generar múltiples buckets en el timeline.

- [ ] **8.3** En `mockStats.ts`: expandir `mitre_tactics` a 4 entradas (ej. `'Initial Access'`, `'Execution'`, `'Persistence'`, `'Lateral Movement'`).

---

### Fase 9 — Validación

- [ ] **9.1** Levantar frontend en modo mock (`VITE_MOCK_DATA=true`) y verificar los tres tooltips visualmente.
- [ ] **9.2** Confirmar con `tsc --noEmit` que no hay errores de tipos en los nuevos `TimelineRow`, `MitreTacticRow`, `ThreatLevelRow`.
- [ ] **9.3** Verificar en modo real (sin mock) que el degradado `techniques: []` / `topPaths: []` no rompe el tooltip cuando la API retorna `KillChainCount[]`.

---

## Árbol de archivos afectados

```
frontend/src/
├── types/
│   └── api.ts                      ← +TechniqueRef, +MitreTacticRow, +TimelineRow, +ThreatLevelRow
├── hooks/
│   └── useStats.ts                 ← timelineData enriquecido, mitreTactics→MitreTacticRow, +threatLevelData
├── components/
│   └── TooltipShell.tsx            ← NUEVO: TooltipShell, TooltipRow, TooltipDivider
├── data/
│   ├── mockThreats.ts              ← Corrección de tipos + 2do mock
│   └── mockStats.ts                ← Expandir mitre_tactics
└── features/dashboard/
    ├── AttackTimeline.tsx          ← +TimelineTooltip, wire content prop
    ├── MitreTacticsChart.tsx       ← +MitreTacticTooltip, wire content prop
    ├── ThreatLevelPie.tsx          ← +ThreatLevelTooltip, wire content prop
    └── DashboardPage.tsx           ← threatLevelData → ThreatLevelPie
```

---

## Decisiones de diseño a confirmar antes de implementar

| # | Decisión | Opción A | Opción B |
|---|---|---|---|
| 1 | ¿`user_agent`/`response_code` en timeline? | Pasar `logs: LogEntry[]` a `useStats` (requiere `useLogs`) | Omitir, mostrar `—` siempre |
| 2 | ¿`TooltipShell` en `components/` o co-ubicado? | `components/` (reutilizable) | `features/dashboard/` (más acotado) |
| 3 | ¿Barra de progreso en ThreatLevel tooltip? | Incluir (más impacto visual) | Omitir (más limpio) |

