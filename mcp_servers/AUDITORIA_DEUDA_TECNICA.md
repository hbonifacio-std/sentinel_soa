# Auditoría de Deuda Técnica — `mcp_servers/`

**Proyecto:** Sentinel SOA — MCP Log Analysis Server  
**Fecha:** 2026-07-08  
**Alcance:** `mcp_servers/log_analysis_server/` (31 archivos fuente + pruebas)  
**Estado funcional:** El sistema opera según lo esperado. **131 pruebas pasan** con **84% de cobertura** global.

---

## 1. Resumen ejecutivo

El servidor MCP de análisis de logs tiene una base sólida: contratos Pydantic claros, factory de proveedores LLM, motor heurístico determinista, capa de prompts centralizada y suite de pruebas unitarias e integración. La deuda técnica principal **no es funcional**, sino **estructural**: módulos demasiado grandes, duplicación de utilidades, acoplamiento a singletons globales y código muerto o inconsistente heredado de iteraciones previas.

Este documento prioriza mejoras alineadas con **SOLID** y buenas prácticas, preservando el comportamiento actual y apoyándose en las pruebas existentes como red de seguridad.

| Dimensión | Estado | Observación |
|-----------|--------|-------------|
| Funcionalidad | ✅ Estable | Herramientas MCP registradas y probadas |
| Pruebas | ✅ 131/131 OK | Cobertura 84%; gaps en `prompt_factory` (41%) y `forensic_nlq` (64%) |
| Arquitectura | ⚠️ Mejorable | God modules, singletons, duplicación |
| Mantenibilidad | ⚠️ Media | `analyze_activity.py` concentra demasiadas responsabilidades |
| Extensibilidad | ✅ Parcial | Factory de LLM bien diseñada; falta DI consistente |
| Consistencia de contratos | ⚠️ Baja | Respuestas de error con formas distintas entre tools |

---

## 2. Mapa arquitectónico actual

```
mcp_servers/log_analysis_server/
├── server.py                 # FastMCP: transporte + registro de tools + logging
├── config.py                 # Pydantic Settings (singleton server_settings)
├── tools/
│   ├── analyze_activity.py   # Orquestación principal (~715 líneas)
│   ├── forensic_nlq.py       # NLQ → Mongo + reportes forenses
│   └── threat_context.py     # Historial de alertas por IP
├── services/
│   ├── heuristics_engine.py  # Scoring determinista
│   ├── translate_mongo.py    # Traducción NL → MongoDB filter
│   ├── prompt_factory.py     # Templates por proveedor (web, forensic, NLQ)
│   └── prompt_builder.py     # Extracción de telemetría + prompts legacy Gemini/Ollama
├── llm_providers/            # Adapter pattern: gemini, ollama, openai, groq
├── models/                   # Contratos Pydantic entrada/salida
└── store/alert_store.py      # Singleton in-memory con lock
```

**Flujo principal (`analyze_web_activity`):**

```
MCP tool (server.py)
  → execute_analyze_web_activity (tools/analyze_activity.py)
      → ThreatHeuristics.analyze (determinista)
      → alert_store.get_history_by_ip (contexto temporal)
      → LLMAnalyzer.analyze_with_context (opcional, con fallback)
      → merge indicadores + MITRE + ThreatAssessment
      → alert_store.add_assessment
```

---

## 3. Hallazgos por principio SOLID

### 3.1 Single Responsibility Principle (SRP) — Prioridad ALTA

| Hallazgo | Ubicación | Impacto | Evidencia |
|----------|-----------|---------|-----------|
| **God module de análisis** | `tools/analyze_activity.py` (~715 líneas) | Dificulta cambios aislados en MITRE, indicadores, recomendaciones o LLM | Contiene: matriz MITRE, normalización de indicadores, `LLMAnalyzer`, orquestación, generación de recomendaciones, enriquecimiento MITRE |
| **Servidor mezcla capas** | `server.py` | Transport MCP + logging bootstrap + payloads de error duplicados | Líneas 130–149: respuesta de error con 15+ campos inline que replican `ThreatAssessment` |
| **Doble responsabilidad en prompts** | `prompt_builder.py` + `prompt_factory.py` | Confusión sobre cuál es la fuente de verdad | `prompt_factory` usa `_extract_telemetry_data` de `prompt_builder`; `build_full_prompt` / `build_optimized_json_prompt` coexisten con templates de factory |
| **Heurísticas monolíticas** | `services/heuristics_engine.py` | Aceptable hoy; crecerá si se añaden reglas | Clase con 7 sub-análisis estáticos en un solo archivo |

**Recomendación:** Extraer submódulos con responsabilidad única:

```
tools/analyze_activity/
├── orchestrator.py      # execute_analyze_web_activity (flujo)
├── llm_analyzer.py      # clase LLMAnalyzer
├── mitre_mapper.py      # MITRE_MATRIX + _enrich_with_mitre_dictionary
├── indicators.py        # normalización y merge de indicadores
└── recommendations.py   # _generate_recommendation
```

---

### 3.2 Open/Closed Principle (OCP) — Prioridad MEDIA

| Hallazgo | Ubicación | Impacto |
|----------|-----------|---------|
| **Factory de proveedores bien aplicada** | `llm_providers/__init__.py` | ✅ Añadir un proveedor nuevo requiere solo un branch + clase; no toca orquestación |
| **Matriz MITRE hardcodeada** | `analyze_activity.py` líneas 47–162 | Añadir técnicas exige editar el módulo central |
| **Selección de modelo acoplada a settings** | `LLMAnalyzer.__init__`, `_generate_llm_forensic_report` | Dificulta inyectar catálogos alternativos (tests, multi-tenant) |
| **Lógica de triage fija** | `forensic_nlq.py` | Umbrales `_LOW_VOLUME_LOG_THRESHOLD`, `_SAMPLED_LOG_COUNT` no configurables |

**Recomendación:** Externalizar MITRE matrix y umbrales de sampling a `config.py` o archivos JSON en `data/`. Mantener factory como punto de extensión para nuevos LLM.

---

### 3.3 Liskov Substitution Principle (LSP) — Prioridad MEDIA

| Hallazgo | Ubicación | Impacto |
|----------|-----------|---------|
| **Interfaz mínima correcta** | `LLMProviderInterface` | `call_model` + `validate_response` son intercambiables |
| **Métodos extra no contractuales** | `GeminiProvider.build_analysis_prompt`, idem OpenAI/Groq | No forman parte de la interfaz; el flujo real usa `prompt_factory.build_web_activity_prompt` — los métodos del provider **no se invocan en producción** |
| **Validación inconsistente entre providers** | Ollama normaliza aliases; Gemini filtra manualmente; Groq/OpenAI tienen su propia lógica | Comportamiento sustituible en happy path, pero divergente en respuestas malformadas |

**Recomendación:**
1. Eliminar `build_analysis_prompt` de providers o moverlo a la interfaz si se decide usar polimorfismo de prompts.
2. Extraer `_normalize_llm_response(parsed: dict) -> LLMResponse` a clase base o mixin compartido.

---

### 3.4 Interface Segregation Principle (ISP) — Prioridad BAJA

| Hallazgo | Impacto |
|----------|---------|
| `LLMProviderInterface` expone `health_check()` que no usa el orquestador | Interfaces pequeñas en general; health_check podría ser protocolo separado `HealthCheckable` |
| `get_provider_config()` devuelve dict plano con todas las claves de todos los providers | Cada provider recibe más de lo que necesita |

**Recomendación:** Introducir `ProviderConfig` tipado por proveedor o pasar solo los campos requeridos en el factory.

---

### 3.5 Dependency Inversion Principle (DIP) — Prioridad ALTA

| Hallazgo | Ubicación | Impacto |
|----------|-----------|---------|
| **Singletons globales** | `server_settings`, `alert_store` | Acoplamiento directo; tests compensan con monkeypatch |
| **Inyección parcial existente** | `TranslateMongo(..., provider=...)` | ✅ Buen patrón, no replicado en `LLMAnalyzer` ni forensic report |
| **Import directo de `shared.rules_seed`** | `heuristics_engine.py` | Acopla MCP a layout de datos del monorepo |
| **Función muerta con config inexistente** | `translate_mongo.py:125-132` | Referencia `server_settings.default_translator_model_id` que **no existe** en `config.py` |

**Recomendación:** Introducir contenedor ligero o factories inyectables:

```python
@dataclass
class AnalysisDependencies:
    settings: LogAnalysisServerSettings
    alert_store: InMemoryAlertStore
    provider_factory: Callable[..., LLMProviderInterface] = create_llm_provider
```

Usar defaults en producción (`AnalysisDependencies(settings=server_settings, ...)`) y mocks en tests sin monkeypatch global.

---

## 4. Hallazgos transversales (DRY, dead code, contratos)

### 4.1 Duplicación crítica (DRY)

| Utilidad duplicada | Copias | Acción |
|--------------------|--------|--------|
| `_extract_json_object` | `ollama_provider`, `groq_provider`, `translate_mongo`, `forensic_nlq` | Extraer a `services/json_utils.py` |
| Normalización de respuesta LLM | Cada provider implementa su variante | Mover a `llm_providers/response_normalizer.py` |
| Payload de error MCP | `server.py` inline vs `ThreatAssessment` schema | Factory `build_error_assessment(...)` reutilizable |
| Import duplicado | `analyze_activity.py` líneas 23–24 | Eliminar línea repetida de `build_web_activity_prompt` |

### 4.2 Código muerto o legacy

| Elemento | Archivo | Notas |
|----------|---------|-------|
| `_extract_status_codes`, `_URI_PATTERN` | `forensic_nlq.py` | No referenciados; restos de parser regex pre-LLM |
| `generate_mongo_query_from_nl()` (función módulo) | `translate_mongo.py:125-132` | No usada por `server.py`; referencia config inexistente |
| `build_optimized_json_prompt` | `prompt_builder.py` | Solo usada en test de integración; flujo productivo usa `prompt_factory` |
| `build_analysis_prompt` en providers | gemini/openai/groq | Dead code en runtime |

### 4.3 Inconsistencias de contrato API

| Tool | Campo inconsistente | Detalle |
|------|---------------------|---------|
| `get_threat_context` | `alerts_found` vs `record_count` | Éxito devuelve `alerts_found`; error en `server.py` devuelve `record_count` |
| `ForensicReportInput` | `model_id` requerido en modelo | `server.py` lo trata como opcional con default de settings — el modelo Pydantic interno puede fallar si no se pasa |
| Recomendaciones LLM vs heurísticas | Semántica opuesta | Prompt pide recomendaciones estratégicas (NIST); `_generate_recommendation` genera acciones reactivas ("BLOCK IP") — diseño intencional pero documentación insuficiente |

### 4.4 Gestión de recursos

| Problema | Archivo | Riesgo |
|----------|---------|--------|
| `OllamaProvider._get_client()` crea nuevo `httpx.AsyncClient` sin cerrar el anterior | `ollama_provider.py:62-76` | Fuga de conexiones bajo carga |
| Sin hook de shutdown en `server.py` | `server.py` | Providers con clientes HTTP no se cierran al apagar |

### 4.5 Configuración y operabilidad

| Problema | Detalle |
|----------|---------|
| Catálogo de modelos hardcodeado | `config.py` líneas 37–47; cambiar modelos requiere deploy de código |
| `available_models` no sobreescribible por env | No hay `AVAILABLE_MODELS_JSON` ni similar |
| Fail-fast en import de config | Correcto para subprocess MCP, pero dificulta tests sin env completo |
| Typo en enum | `KillChainPhaseEnum.ACTION_ON_OBJETIVES` → debería ser `OBJECTIVES` (breaking change si hay consumidores) |

### 4.6 Seguridad y robustez

| Aspecto | Estado |
|---------|--------|
| Secretos con `SecretStr` | ✅ Bien implementado |
| Sanitización de payloads en prompts | ✅ Truncado y limpieza de UA |
| Logging de respuestas LLM | ⚠️ Primeros 300–500 chars en DEBUG; revisar en producción |
| Excepciones genéricas | ⚠️ `except Exception` amplio en tools; dificulta diagnóstico |

---

## 5. Métricas de calidad (baseline)

Comando de verificación:

```bash
.venv\Scripts\pytest mcp_servers/log_analysis_server/test --cov=mcp_servers/log_analysis_server --cov-report=term-missing -q
```

| Módulo | Cobertura | Deuda asociada |
|--------|-----------|----------------|
| `tools/analyze_activity.py` | 77% | Ramas fallback LLM, `_generate_recommendation`, MITRE edge cases |
| `tools/forensic_nlq.py` | 64% | Sampling, timeout LLM, errores malformados |
| `services/prompt_factory.py` | 41% | Ramas no-Ollama, truncado por tokens |
| `llm_providers/*` | 52–70% | health_check, errores de red |
| `server.py` | 72% | `main()` / startup HTTP-stdio |
| **TOTAL** | **84%** | Objetivo post-refactor: ≥90% sin regresiones |

---

## 6. Plan de ejecución por fases

> **Principio rector:** Refactor incremental con pruebas verdes en cada fase. No cambiar comportamiento observable del contrato MCP salvo correcciones de bugs documentadas.

### Fase 0 — Preparación (0.5 día)

- [ ] Congelar baseline: ejecutar suite completa y guardar reporte de cobertura.
- [ ] Añadir `pytest.ini` o marker `@pytest.mark.unit` / `@pytest.mark.integration` si aún no están documentados en README del módulo.
- [ ] Definir Definition of Done por fase: **131+ tests OK**, cobertura no decrece.

### Fase 1 — Quick wins sin cambio arquitectónico (0.5 día) ✅ COMPLETADA

**Objetivo:** Reducir ruido y bugs latentes con diffs mínimos.

| # | Tarea | Archivos | Estado |
|---|-------|----------|--------|
| 1.1 | Eliminar import duplicado | `analyze_activity.py` | ✅ |
| 1.2 | Eliminar código muerto: `_extract_status_codes`, `_URI_PATTERN`, constantes regex sin uso | `forensic_nlq.py` | ✅ |
| 1.3 | Eliminar `generate_mongo_query_from_nl` rota en `translate_mongo.py` | `translate_mongo.py` | ✅ |
| 1.4 | Unificar respuesta de error de `get_threat_context` → `alerts_found` | `server.py`, `test_server.py` | ✅ |
| 1.5 | `ForensicReportInput.model_id` opcional; resolución en `_generate_llm_forensic_report` | `forensic_input.py`, `forensic_nlq.py` | ✅ |
| 1.6 | `OllamaProvider._get_client()` reutiliza instancia única | `ollama_provider.py`, `test_providers.py` | ✅ |

**Verificación:** `pytest mcp_servers/log_analysis_server/test -q`

### Fase 2 — Extracción DRY (1 día) ✅ COMPLETADA

**Objetivo:** Un solo lugar para parsing JSON y normalización LLM.

| # | Tarea | Entregable | Estado |
|---|-------|------------|--------|
| 2.1 | Crear `services/json_utils.py` con `extract_json_object(text) -> dict` | Reemplazar 4 copias | ✅ |
| 2.2 | Crear `llm_providers/response_normalizer.py` con `normalize_llm_decision` + `parse_llm_decision_response` | Unificar aliases en todos los providers | ✅ |
| 2.3 | Crear `tools/error_responses.py` con builders tipados para errores MCP | Eliminar dicts inline en `server.py` | ✅ |
| 2.4 | Tests unitarios dedicados | `test_json_utils`, `test_response_normalizer`, `test_error_responses` | ✅ |

### Fase 3 — Descomposición SRP de `analyze_activity` (3–5 días) ✅ COMPLETADA

**Objetivo:** Módulo principal <200 líneas de orquestación.

```
tools/analyze_activity/
├── __init__.py          # re-export execute_analyze_web_activity (compat imports)
├── orchestrator.py
├── llm_analyzer.py
├── mitre_mapper.py
├── indicators.py
└── recommendations.py
```

| # | Tarea | Criterio de aceptación | Estado |
|---|-------|------------------------|--------|
| 3.1 | Mover `MITRE_MATRIX`, `_enrich_with_mitre_dictionary` | Tests MITRE existentes siguen pasando | ✅ |
| 3.2 | Mover funciones `_normalize_*`, `_build_deterministic_indicators` | `test_analyze_activity.py` verde | ✅ |
| 3.3 | Mover `_generate_recommendation` + 7 tests | Añadir 2–3 tests de ramas CRITICAL/HIGH/MEDIUM | ✅ |
| 3.4 | Mover clase `LLMAnalyzer` | Sin cambio en firma pública | ✅ |
| 3.5 | Mantener `from mcp_servers...analyze_activity import execute_analyze_web_activity` | Compatibilidad con `server.py` y orchestrator | ✅ |

### Fase 4 — Dependency Injection ligera (2–3 días)

**Objetivo:** Reducir acoplamiento a singletons sin framework pesado.

| # | Tarea | Detalle |
|---|-------|---------|
| 4.1 | Introducir `AnalysisDependencies` dataclass | Defaults apuntan a singletons actuales |
| 4.2 | Refactor `execute_analyze_web_activity(..., deps: AnalysisDependencies = DEFAULT_DEPS)` | Tests pasan deps mock sin monkeypatch |
| 4.3 | Mismo patrón para `TranslateMongo`, `generate_forensic_report` | Provider inyectable ya existe parcialmente |
| 4.4 | Opcional: `Protocol` para `AlertStore` | Facilita swap a Redis/Mongo en futuro |

### Fase 5 — Consolidación de capa de prompts (2–4 días)

**Objetivo:** Una sola API pública de prompts.

| # | Tarea | Resultado |
|---|-------|-----------|
| 5.1 | Deprecar `AnalysisPromptBuilder.build_full_prompt` / `build_optimized_json_prompt` | Migrar test de integración a `prompt_factory` |
| 5.2 | Mover `get_system_instructions()` a módulo compartido o solo Gemini provider | Eliminar duplicación semántica con `FULL_PROMPT_TEMPLATE` |
| 5.3 | Añadir tests para ramas Gemini/OpenAI en `prompt_factory` | Subir cobertura de 41% → ≥80% |
| 5.4 | Documentar en docstring la diferencia recomendaciones LLM (estratégicas) vs heurísticas (reactivas) | Reduce confusión de mantenedores |

### Fase 6 — Configuración externalizable (1–2 días)

| # | Tarea | Detalle |
|---|-------|---------|
| 6.1 | Soporte `AVAILABLE_MODELS_JSON` en settings | Override del catálogo sin redeploy |
| 6.2 | Externalizar umbrales forensic sampling | Env vars con defaults actuales |
| 6.3 | Externalizar MITRE matrix opcionalmente | JSON en `data/mitre_matrix.json` |

### Fase 7 — Hardening operacional (1–2 días)

| # | Tarea | Detalle |
|---|-------|---------|
| 7.1 | Lifespan hook: cerrar clientes HTTP al shutdown | `server.py` + `ollama_provider.close()` |
| 7.2 | Narrow exceptions: capturar `LLMException`, `ValidationError` explícitamente | Mejor telemetría |
| 7.3 | Corregir typo `ACTION_ON_OBJETIVES` con alias backward-compatible | Enum + migración |

---

## 7. Matriz de priorización

| ID | Hallazgo | Esfuerzo | Impacto | Fase |
|----|----------|----------|---------|------|
| H-01 | God module `analyze_activity.py` | Alto | Alto | 3 |
| H-02 | Duplicación `_extract_json_object` | Bajo | Medio | 2 |
| H-03 | Singletons sin DI | Medio | Alto | 4 |
| H-04 | Código muerto + config rota `default_translator_model_id` | Bajo | Medio | 1 |
| H-05 | Inconsistencia `alerts_found` / `record_count` | Bajo | Medio | 1 |
| H-06 | Fuga httpx en Ollama | Bajo | Medio | 1 |
| H-07 | Prompt layer duplicada | Medio | Medio | 5 |
| H-08 | Cobertura baja `prompt_factory` | Medio | Medio | 5 |
| H-09 | MITRE hardcodeado | Medio | Bajo | 6 |
| H-10 | Métodos muertos en providers | Bajo | Bajo | 1–2 |

---

## 8. Criterios de aceptación globales

1. **Regresión cero:** Todas las pruebas existentes pasan; no se eliminan tests sin reemplazo equivalente.
2. **Cobertura:** ≥90% en `mcp_servers/log_analysis_server` (excluyendo `test/` y `if __name__`).
3. **Imports estables:** `server.py` y `core_orchestrator` no requieren cambios de integración salvo acordado.
4. **Contratos MCP:** Schemas de respuesta documentados; cambios breaking anotados en CHANGELOG interno.
5. **PRs pequeños:** Una fase = uno o más PRs reviewables (<400 líneas netas preferible).

---

## 9. Riesgos y mitigaciones

| Riesgo | Probabilidad | Mitigación |
|--------|--------------|------------|
| Regresión silenciosa en scoring híbrido | Media | Mantener `test_analyze_activity.py` como suite áncora; golden files para casos MITRE |
| Breaking change en JSON de error MCP | Baja | Coordinar con `core_orchestrator` adapters; versionar campo deprecated |
| Refactor de prompts altera respuestas LLM | Media | Tests de contrato mínimo (`test_llm_minimal_contract`); no cambiar templates en fases 1–3 |
| Scope creep | Alta | Respetar orden de fases; posponer multi-tenant y persistencia Redis a backlog |

---

## 10. Backlog post-plan (fuera de alcance inmediato)

- Persistencia de `alert_store` en Redis (stateful MCP en despliegues multi-réplica).
- Rate limiting / circuit breaker por proveedor LLM.
- Observabilidad: métricas Prometheus (latencia por tool, fallos LLM, cache hit heurísticas).
- Alinear `RulesBundle` con `core_orchestrator` vía paquete compartido tipado (eliminar duplicación de dataclass).
- Contract testing formal entre orchestrator ↔ MCP (JSON Schema compartido en `shared/`).

---

## 11. Referencias internas

| Documento | Relación |
|-----------|----------|
| `mcp_servers/audit_report.md` | Plan previo enfocado en cobertura de pruebas (>90%) |
| `plan_test_unitarios.md` | Plan de cobertura para `core_orchestrator` |
| `docs/AI_AGENTS.md` | Integración MCP con agentes |
| `Dockerfile.mcp` | Despliegue del servidor |

---

## 12. Próximo paso recomendado

Comenzar por **Fase 1** (quick wins): bajo riesgo, beneficio inmediato en claridad y eliminación de bugs latentes. Tras Fase 1 verde, abrir PR de **Fase 2** (`json_utils`) como fundamento para refactor de providers y forensic tools.

```bash
# Verificación rápida post-cada fase
.venv\Scripts\pytest mcp_servers/log_analysis_server/test --cov=mcp_servers/log_analysis_server --cov-report=term-missing -q
```
