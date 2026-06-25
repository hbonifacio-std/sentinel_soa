# Auditoria Tecnica Integral

**Proyecto:** Sentinel SOA  
**Fecha:** 2026-06-24  
**Scope:** `core_orchestrator`, `frontend`, `mcp_servers/log_analysis_server`  
**Objetivo:** evaluar deuda tecnica, calidad de codigo (SOLID), escalabilidad, mantenibilidad, buenas practicas y seguridad.

---

## 1) Metodologia usada

1. Revision estatica de codigo y configuracion en:
   - `core_orchestrator/**/*.py`
   - `frontend/src/**/*.{ts,tsx}` + `frontend/package.json` + `frontend/vite.config.ts`
   - `mcp_servers/log_analysis_server/**/*.py`
   - `docker-compose.yml`, `Dockerfile.core`, `Dockerfile.frontend`, `Dockerfile.mcp`
2. Evaluacion de principios SOLID y separacion de responsabilidades por modulo.
3. Analisis de riesgos de seguridad de aplicacion y cadena de suministro.
4. Verificacion de deuda en pruebas, operabilidad y estandarizacion.
5. Escaneo de CVEs con herramienta automatizada sobre dependencias principales (`validate_cves`).

> Nota: este informe se basa en evidencia del repositorio actual y no incluye pruebas de carga/penetracion en runtime.

---

## 2) Resumen ejecutivo

### Estado general (alto nivel)

- **Core Orchestrator:** funcionalmente robusto, pero con deuda en arquitectura (acoplamiento global), operaciones async no controladas y seguridad en gestion de secretos.
- **Frontend:** buena base TypeScript y enrutado protegido, pero alta concentracion de logica en componentes grandes, falta de estandares de calidad automatizados (lint/test), y riesgo de mantenimiento.
- **MCP Server:** potencia tecnica alta (heuristica + LLM + contratos), pero presenta un modulo monolitico muy grande, trazas inseguras (`print`), y riesgos de seguridad/supply-chain.

### Calificacion estimada (1-5)

- **Core Orchestrator:** 3.2/5
- **Frontend:** 2.9/5
- **MCP Server:** 3.0/5
- **Global:** 3.0/5

### Riesgos criticos/prioridad P1

1. Dependencias con CVEs relevantes en backend (`python-jose`, `python-multipart`, `PyJWT`, `starlette`, `requests`).
2. Secretos inseguros por defecto y simulacion de blacklist JWT en memoria (`core_orchestrator/security/redis_sim.py`).
3. Tareas async lanzadas sin control (posible perdida de trabajo/errores silenciosos) en ingestion y analisis.
4. `RulesPage.tsx` (695 lineas) y `analyze_activity.py` (685 lineas) como hotspots de deuda por complejidad.

---

## 3) Hallazgos detallados

## 3.1 Core Orchestrator

### Fortalezas

- Buen uso de `pydantic-settings` y tipado fuerte en config: `core_orchestrator/config.py`.
- Separacion por capas razonable (api/services/security/models/agent).
- Cobertura de pruebas relativamente amplia en `core_orchestrator/test` (unit/integration/performance).
- Controles de auth/RBAC presentes (`get_current_user`, `get_admin_user`, `get_analyst_user`) en `core_orchestrator/security/dependencies.py`.

### Deuda tecnica y calidad (SOLID)

1. **Violacion SRP / clase coordinadora sobredimensionada**  
   `OrchestratorAgent.process_telemetry_window` concentra cache, llamada MCP, parsing, fallback, persistencia y enriquecimiento (`core_orchestrator/agent/orchestrator.py:140-279`).
2. **Acoplamiento fuerte a singletons globales (DIP bajo)**  
   Uso directo de `db`, `get_rules_engine()`, `agent_runner`, `window_manager` en multiples modulos, dificultando test unitario aislado e inversion de dependencias.
3. **Errores ortograficos en API publica interna**  
   `initialize_subsytem` / `shutdown_subsytem` (`core_orchestrator/agent/runner.py:93,137`) y paquete `exeptions/` impactan mantenibilidad y claridad.
4. **Complejidad ciclica en ingestion**  
   Mezcla de persistencia, buffering, lock, trigger y respuesta HTTP dentro de endpoints (`core_orchestrator/api/v1/endpoints/agent_telemetry.py`).

### Escalabilidad y operacion

1. **Polling Redis + `keys("window:*")`**  
   `WindowManager.get_active_windows` usa `KEYS` (`core_orchestrator/services/window_manager.py:56`), costoso en escenarios grandes.
2. **`asyncio.create_task` sin tracking estructurado**  
   Se crean tareas de guardado/analisis sin cola ni backpressure (`agent_telemetry.py:90,140,180,248`; `runner.py:83`).
3. **Locking distribuido correcto pero sin estrategia de reintento/telemetria formal**.

### Seguridad

1. **JWT secret inseguro por defecto en config**  
   `jwt_secret_key` default: `dev-secret-key-change-in-production` (`core_orchestrator/config.py:169-173`).
2. **Blacklist JWT en memoria de proceso**  
   `redis_sim` no persiste entre reinicios ni nodos (`core_orchestrator/security/redis_sim.py`). En despliegues multi-instancia invalida logout global.
3. **CORS configurable, pero `allow_headers=["*"]`**  
   Superficie amplia (`core_orchestrator/main.py:96`).
4. **Logging de eventos potencialmente sensibles**  
   `event.model_dump_json()` se registra completo en ingest (`agent_telemetry.py:86-88`).

### Pruebas y aseguramiento

- Buena base de pruebas en core, pero faltan validaciones de resiliencia async (cancelacion de tareas, perdida de mensajes, fallos Redis/Mongo parciales).

---

## 3.2 Frontend

### Fortalezas

- TypeScript en modo `strict` (`frontend/tsconfig.json:7`).
- Guardas de autenticacion y rol (`RequireAuth`, `RequireRole`).
- Cliente API centralizado con manejo de 401 (`frontend/src/lib/apiClient.ts`).

### Deuda tecnica y calidad (SOLID)

1. **Componente God Object en reglas**  
   `frontend/src/features/rules/RulesPage.tsx` (695 lineas) mezcla UI, validaciones, transformaciones DTO, coordinacion API, estado de modal y mensajeria. Violacion SRP clara.
2. **Acoplamiento fuerte entre capa de UI y contratos de dominio**  
   Conversiones `draftToRule/ruleToUpdatePayload` en la misma pagina, sin capa de servicio de dominio.
3. **Uso de APIs bloqueantes de navegador para flujos criticos**  
   `window.prompt` en operaciones de desactivacion (`RulesPage.tsx:276,280`) afecta UX, testabilidad y control transaccional.

### Mantenibilidad y escalabilidad

1. **Sin suite de pruebas frontend**  
   No se encontraron `*.test.*`/`*.spec.*` en `frontend/`.
2. **Sin script de lint/format/checks en `package.json`**  
   Solo `dev/build/preview` (`frontend/package.json:6-10`).
3. **Estado global correcto (Zustand), pero sin politicas de invalidacion/cache estructurado por feature**.

### Seguridad

1. **Persistencia de token en `sessionStorage`**  
   Aceptable para SPA, pero expuesto ante XSS (`frontend/src/store/authStore.ts`). Se requieren controles CSP y hardening de contenido.
2. **Riesgo en Vite dev server expuesto en red**  
   `server.host = true` (`frontend/vite.config.ts:16`) + CVEs recientes en Vite (ver seccion CVEs).

---

## 3.3 MCP Server (`mcp_servers/log_analysis_server`)

### Fortalezas

- Arquitectura conceptual potente: heuristica deterministica + LLM + validacion de contrato de salida.
- Patrón de proveedor LLM desacoplado por interfaz (`llm_providers/base.py`).
- Pruebas de contrato minimo LLM y contexto historico presentes en `test/integration`.

### Deuda tecnica y calidad (SOLID)

1. **Modulo monolitico de alta complejidad**  
   `tools/analyze_activity.py` (685 lineas) combina: taxonomia MITRE, normalizacion, heuristicas, fallbacks, persistencia, politicas de score, logging y orquestacion LLM.
2. **Violacion SRP en `LLMAnalyzer` + flujo principal**  
   Mismo modulo controla inicializacion provider, prompting, validacion, combinacion heuristica y salida final.
3. **Acoplamiento hardcoded de reglas y taxonomias**  
   Diccionarios y reglas estaticas embebidas complican evolucion/versionado externo.

### Escalabilidad y operacion

1. **Store en memoria para alertas historicas**  
   `InMemoryAlertStore` limita horizontal scaling y persistencia (`store/alert_store.py`).
2. **Concurrencia interna con lock de hilo, sin estrategia distribuida** para multiples instancias.

### Seguridad

1. **`print(prompt)` y `print(response_text)` en pipeline LLM**  
   Exposicion de datos sensibles/telemetria en salida (`tools/analyze_activity.py:515,518`).
2. **Manejo de errores devuelve detalle de excepcion al consumidor**  
   Riesgo de leak de informacion interna (`server.py:128`, `threat_context.py:66`).
3. **Transporte HTTP sin evidencia de mTLS/auth de canal MCP**  
   `core_orchestrator/agent/mcp_client.py` usa `http://{host}:{port}/mcp`.

---

## 4) Analisis SOLID (por modulo)

## 4.1 SRP (Single Responsibility)

- **Debil:**
  - `core_orchestrator/agent/orchestrator.py::process_telemetry_window`
  - `frontend/src/features/rules/RulesPage.tsx`
  - `mcp_servers/log_analysis_server/tools/analyze_activity.py`
- **Impacto:** alta complejidad ciclomatica, mayor costo de cambio, mayor riesgo de regresiones.

## 4.2 OCP (Open/Closed)

- **Parcial:** proveedores LLM estan relativamente abiertos a extension (`llm_providers`).
- **Debil:** reglas MITRE y logica de mapeo en `analyze_activity.py` requieren modificar codigo central para nuevos casos.

## 4.3 LSP (Liskov)

- **Aceptable** en jerarquia de proveedores, sin violaciones evidentes en contrato base.

## 4.4 ISP (Interface Segregation)

- **Aceptable** en interfaz LLM, pero faltan interfaces de puertos para persistencia/cache/cola en core.

## 4.5 DIP (Dependency Inversion)

- **Debil en backend/core** por uso de singletons globales (`db`, `agent_runner`, `window_manager`, `get_rules_engine`).
- **Impacto:** pruebas unitarias menos aisladas y mayor friccion para sustituir infraestructura.

---

## 5) Riesgos de seguridad y cadena de suministro

## 5.1 Dependencias con CVE (evidencia automatizada)

### Python

- `starlette==0.41.3` (multiples CVEs DoS/path/security semantics).
- `requests==2.32.3` (CVE-2024-47081, entre otras).
- `python-jose==3.3.0` (**incluye CVE critica de confusion de algoritmos**).
- `python-multipart==0.0.9` (multiples CVEs DoS/parsing).
- `PyJWT==2.10.1` (vulnerabilidades reportadas en versiones escaneadas).

### NPM

- `vite==5.4.19` con multiples CVEs reportadas por herramienta (principalmente entorno dev server / file serving).

> Recomendacion inmediata: actualizar dependencias con estrategia de compatibilidad y pruebas de regresion en pipeline.

## 5.2 Configuracion e infraestructura

1. Imagen `mongo:latest` en compose (`docker-compose.yml:159`) -> falta pin por digest/version.
2. Contenedores Python/Node corren como root por defecto en Dockerfiles (`Dockerfile.core`, `Dockerfile.mcp`, `Dockerfile.frontend`).
3. Secretos de ejemplo con aspecto real en compose (`docker-compose.yml:130,145`) deben eliminarse o reemplazarse por placeholders no validos.

---

## 6) Mapa de deuda tecnica priorizada

| Prioridad | Hallazgo | Impacto | Esfuerzo | Modulo |
|---|---|---|---|---|
| P1 | CVEs criticas/altas en dependencias backend | Seguridad y compliance | M | Core + MCP |
| P1 | `print` de prompt/respuesta LLM | Riesgo de fuga de datos | S | MCP |
| P1 | Secretos por defecto inseguros / blacklist JWT en memoria | Seguridad/autenticacion | M | Core |
| P1 | `RulesPage.tsx` y `analyze_activity.py` monoliticos | Mantenibilidad y regresiones | M/L | Frontend + MCP |
| P2 | `KEYS window:*` + polling | Escalabilidad Redis | M | Core |
| P2 | Tareas async sin cola/backpressure | Robustez operativa | M | Core |
| P2 | Falta de tests frontend | Calidad y velocidad de cambio | M | Frontend |
| P3 | Nomenclatura/typos (`subsytem`, `exeptions`) | Deuda semantica | S | Core |

---

## 7) Plan de accion detallado

## Fase 0 (0-7 dias) - Contencion y seguridad minima

- [ ] Remover `print(prompt)` y `print(response_text)` en `mcp_servers/log_analysis_server/tools/analyze_activity.py`.
- [ ] Forzar `JWT_SECRET_KEY` sin default inseguro en produccion (`core_orchestrator/config.py`).
- [ ] Sustituir `redis_sim` para blacklist por Redis real (o feature flag estricto solo dev).
- [ ] Congelar versiones base en `docker-compose.yml` (`mongo`, etc.) y evitar `latest`.
- [ ] Rotar secretos visibles en compose/ejemplos.

**Resultado esperado:** reduccion inmediata de superficie de fuga y posture de seguridad.

## Fase 1 (1-4 semanas) - Estabilizacion tecnica

- [ ] Upgrade de dependencias criticas:
  - `python-jose` >= 3.4.0
  - `python-multipart` >= 0.0.31
  - `PyJWT` a version recomendada por seguridad
  - `requests` >= 2.33.0
  - revisar upgrade de `starlette`/`fastapi` compatibles
  - `vite` a rama segura compatible
- [ ] Agregar pipeline CI con:
  - lint Python (`ruff`/`flake8`) + type checks (`mypy` opcional)
  - lint frontend (`eslint`) + formato (`prettier`)
  - SCA automatizado (pip-audit/npm audit/Dependabot)
- [ ] Introducir politicas de logging seguro (redaccion de campos sensibles).

**KPIs:**
- 0 dependencias en severidad critica.
- 100% PRs con lint + test obligatorio.

## Fase 2 (1-2 meses) - Refactor orientado a SOLID

### Core

- [ ] Extraer `process_telemetry_window` en casos de uso:
  - `CacheLookupService`
  - `McpAnalysisService`
  - `AnalysisPersistenceService`
  - `ThreatContextEnrichmentService`
- [ ] Reemplazar acceso a singletons por inyeccion de dependencias/puertos (DIP).
- [ ] Reemplazar `KEYS` por `SCAN` o indices de ventanas y/o eventos de expiracion.
- [ ] Sustituir `create_task` ad-hoc por cola (Redis Streams/Celery/RQ) con retries y DLQ.

### Frontend

- [ ] Dividir `RulesPage.tsx` en:
  - hooks (`useRulesQuery`, `useRuleEditor`, `useVersionActions`)
  - componentes (`RulesTable`, `RuleEditorModal`, `VersionPanel`)
  - mapper de dominio (`rulesMappers.ts`)
- [ ] Agregar pruebas:
  - unitarias para mappers/hooks
  - integration/UI (React Testing Library + Vitest)

### MCP

- [ ] Dividir `analyze_activity.py` en modulos por responsabilidad:
  - `indicator_normalizer.py`
  - `mitre_mapper.py`
  - `verdict_builder.py`
  - `llm_adapter_service.py`
- [ ] Externalizar matriz MITRE y pesos a configuracion versionada.

**KPIs:**
- Reducir archivos > 400 lineas en hotspots.
- Reducir complejidad por funcion principal >30%.

## Fase 3 (2-4 meses) - Escalado y madurez operativa

- [ ] Introducir observabilidad completa (OpenTelemetry, trazas distribuidas, SLI/SLO).
- [ ] Implementar arquitectura event-driven para pipeline de analisis.
- [ ] Persistir historial de alertas de MCP en storage central (Redis/Mongo) con TTL.
- [ ] Hardening de contenedores:
  - usuario no-root
  - imagenes base minimizadas
  - escaneo de imagenes (Trivy/Grype)
- [ ] Politicas de seguridad de frontend:
  - CSP estricta
  - protecciones de cabeceras (si aplica en proxy/nginx)

---

## 8) Recomendaciones de arquitectura objetivo

1. **Hexagonal/Ports & Adapters en Core** para desacoplar dominio de infraestructura.
2. **BFF liviano + frontend por features** para escalar equipo/UI.
3. **MCP como servicio stateless** con estado externo compartido.
4. **Estandar de contratos** (pydantic/jsonschema) versionados entre Core y MCP.

---

## 9) Conclusiones

- El proyecto tiene una base funcional avanzada y bien orientada a seguridad ofensiva/defensiva, pero acumula deuda en **modulos monoliticos**, **acoplamiento global**, y **higiene de seguridad operacional**.
- La prioridad inmediata debe ser: **actualizacion de dependencias vulnerables, eliminacion de fugas de logs, y robustecimiento de autenticacion/secretos**.
- Con el plan propuesto por fases, es realista llevar la plataforma a un estado de **escalabilidad y mantenibilidad empresarial** en 8-16 semanas.

---

## 10) Anexos de evidencia (archivos clave revisados)

- `core_orchestrator/agent/orchestrator.py`
- `core_orchestrator/agent/runner.py`
- `core_orchestrator/services/window_manager.py`
- `core_orchestrator/api/v1/endpoints/agent_telemetry.py`
- `core_orchestrator/security/jwt_utils.py`
- `core_orchestrator/security/redis_sim.py`
- `frontend/src/features/rules/RulesPage.tsx`
- `frontend/src/lib/apiClient.ts`
- `frontend/src/store/authStore.ts`
- `frontend/package.json`
- `mcp_servers/log_analysis_server/tools/analyze_activity.py`
- `mcp_servers/log_analysis_server/server.py`
- `mcp_servers/log_analysis_server/llm_providers/*.py`
- `docker-compose.yml`
- `Dockerfile.core`
- `Dockerfile.frontend`
- `Dockerfile.mcp`

