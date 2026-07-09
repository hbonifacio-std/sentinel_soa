# Auditoría Técnica Integral — Sentinel SOA
**Alcance:** `core_orchestrator` (FastAPI), `mcp_servers/log_analysis_server` (MCP), `frontend` (React)
**Metodología:** Revisión estática de código fuente sobre el repositorio actual.

---

## 1. Frente de Seguridad (Security)

### MCP (`mcp_servers/log_analysis_server`)
- **Confianza ciega en el emisor, no en el LLM.** Las tools (`analyze_web_activity`, `get_threat_context`, ver `server.py`) reciben argumentos ya estructurados por Pydantic (`WebActivityWindowInput`), lo cual mitiga inyección de prompt clásica hacia el modelo. Sin embargo, **no existe ningún control de autorización a nivel de tool**: cualquier cliente MCP que logre conectarse al puerto 8080 del `mcp_server` puede invocar `analyze_web_activity` con un `rules_bundle` arbitrario (`_extract_rules_bundle` en `analyze_activity.py` solo valida *forma*, no *origen*), alterando de facto el scoring de amenazas sin autenticarse.
- **Canal Core↔MCP sin autenticación.** `mcp_client.py` abre un `streamable_http_client` hacia `http://mcp_server:8080/mcp` sin token, mTLS ni cabecera de autenticación. Dentro de la red Docker (`sentinel_net`) esto se mitiga parcialmente por aislamiento de red, pero es un punto ciego si el `mcp_server` llegara a exponerse (p. ej. por error de configuración de puertos).
- **Salida del LLM tratada como dato, no como código** (`_extract_llm_decision_fields` filtra a 3 campos): buena práctica — evita que el LLM inyecte campos de gobernanza (MITRE, score) directamente.

### FastAPI (`core_orchestrator`)
- **CRÍTICO — Ausencia total de autenticación/autorización.** Ningún endpoint de `agent_telemetry.py`, `analytics.py` ni `rules_management.py` exige token, API key o sesión. Esto significa que **cualquier persona con acceso de red al puerto 8000 puede**:
  - Inyectar telemetría falsa (`/ingest/raw`, `/ingest/batch`).
  - Leer y modificar el motor de reglas heurísticas de detección (`POST/PATCH/DELETE /api/v1/rules/*`), incluyendo activar versiones de reglas (`/versions/activate/{hash}`), es decir, **desactivar o envenenar la detección de amenazas del sistema completo**.
  - Marcar alertas como revisadas/resueltas (`/analytics/reports/{id}/resolve`), ocultando evidencia de incidentes reales.
- **CRÍTICO — CORS mal configurado.** En `main.py`:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_credentials=True,
      ...
  )
  ```
  La combinación `allow_origins=["*"]` + `allow_credentials=True` es una antipatrón reconocido (y en navegadores modernos es inválida per-spec, forzando comportamientos inconsistentes entre clientes). En producción permite que cualquier origen realice peticiones con credenciales.
- **Rate limiting incompleto.** `slowapi` (`services/limiter.py`) está integrado y se usa en `rules_management.py` (10-20/min) y parcialmente en `analytics.py` (5/min), pero **no se aplica a `agent_telemetry.py`** (`/ingest/single`, `/ingest/batch`, `/ingest/raw`, `/flush`), que son justamente los endpoints que disparan llamadas costosas al LLM. Esto es simultáneamente un hallazgo de seguridad (DoS) y de escalabilidad/costo (ver Frente 3).
- **Secretos hardcodeados en app víctima.** `victim_app/main.py` tiene `SECRET_KEY = "a_very_secret_key..."` — aceptable porque es intencionalmente el laboratorio vulnerable de simulación, pero debe documentarse explícitamente como tal para que no se reutilice por error en un despliegue real.

### React (`frontend`)
- No hay manejo de tokens visible en `apiClient.ts` (coherente con la ausencia de auth en el backend); si se añade autenticación, se deberá definir dónde vive el token (evitar `localStorage` para JWT de sesión larga, preferir cookie `httpOnly` + `SameSite=strict`).
- El contenido generado/derivado del análisis de IA (`reasoning_summary`, `recommendation`, indicadores) se renderiza siempre como texto (`{value}`, `<pre>{recommendation}</pre>`) — **no se detectó uso de `dangerouslySetInnerHTML`**, por lo que el riesgo de XSS vía contenido de IA es bajo en los componentes revisados (`ReasoningBreakdown.tsx`, `MitigationTimeline.tsx`, `JsonViewer.tsx`).

---

## 2. Frente de Rendimiento (Performance)

### FastAPI / MCP
- **`print()` en el camino caliente de análisis** (`analyze_activity.py`, método `LLMAnalyzer.analyze_with_context`):
  ```python
  prompt = provider.build_analysis_prompt(telemetry, history)
  print(prompt)
  response_text = await provider.call_model(prompt)
  print(response_text)
  ```
  Esto ocurre en **cada** ventana de telemetría analizada. `print()` a stdout es I/O síncrono bloqueante dentro de una corrutina async, compite con el event loop, infla los logs de contenedor sin control de nivel (`DEBUG`/`INFO`) y **filtra telemetría cruda (posibles credenciales, payloads) fuera del pipeline de logging estructurado**. Es un hallazgo de rendimiento y de higiene de seguridad simultáneamente.
- **`window_manager.get_active_windows()` usa `KEYS "window:*"`** (`services/window_manager.py`). `KEYS` es O(N) y bloquea el servidor Redis mientras escanea todo el keyspace; se ejecuta cada 5s desde `_window_processor_task` en `agent/runner.py`. Con miles de IPs activas esto degrada Redis para *todos* los consumidores (incluido el rate limiter, que también usa Redis).
- Los proveedores LLM (`GeminiProvider` con `asyncio.to_thread`, `OpenAIProvider`/`GroqProvider` con clientes async nativos, `OllamaProvider` con `httpx.AsyncClient`) están correctamente implementados sin bloquear el event loop — buena práctica.

### React
- `useThreats`/`useStats`/`useLogs` recalculan agregaciones pesadas (`useMemo` sobre `timelineData`, `mitreTactics`) en cliente; aceptable para volúmenes de dashboard, pero con *polling* habilitado (`VITE_POLLING_INTERVAL_MS`) y tablas grandes, cada tick recalcula todo el `Map` de agregación — no crítico, pero convendría memoizar por fuente de datos si el dataset crece.
- `LogsTable.tsx` usa `@tanstack/react-virtual` correctamente — buena práctica para listas grandes.

---

## 3. Frente de Escalabilidad (Scalability)

- **CRÍTICO — Sesión MCP única y global sin reconexión.** `MCPClientManager` (`agent/mcp_client.py`) abre **una sola** `ClientSession` en el arranque (`initialize_subsytem` → `_init_mcp_background`) y la reutiliza para *todas* las llamadas concurrentes (`call_tool`). No hay pool de conexiones, no hay *lock* que serialice el acceso a la sesión compartida, y **no existe lógica de reconexión** si el `mcp_server` se reinicia o la conexión cae: todas las llamadas subsecuentes fallarán silenciosamente (capturadas y devueltas como `{"error": ...}`) hasta que se reinicie manualmente el `core_orchestrator`. Con múltiples ventanas de telemetría procesándose en paralelo (`asyncio.create_task` en `agent_telemetry.py` y `runner.py`), esto es un cuello de botella y un punto único de fallo.
- **Estado en memoria del `mcp_server` no es horizontal-scaling-safe.** `alert_store` (`store/alert_store.py`) es un singleton **en memoria del proceso** protegido con `threading.Lock`. Si se replican contenedores `mcp_server` detrás de un balanceador, el historial de alertas por IP (`get_history_by_ip`, usado para correlación temporal en el prompt) quedará fragmentado entre réplicas, degradando silenciosamente la calidad de la detección de campañas persistentes — sin error visible.
- **Sin límite de peticiones en los endpoints más costosos.** Como se mencionó en el Frente 1/2, `/ingest/*` y `/flush` no tienen rate limiting, lo que impide controlar el número de invocaciones a proveedores LLM de pago (OpenAI/Gemini/Groq) bajo carga — riesgo de facturación descontrolada además de degradación de servicio.
- El resto del diseño (Redis como *shared state* para ventanas, locks distribuidos vía `redis_client.lock`, caché de reglas en Redis DB3) sí está bien orientado a *stateless scaling* del `core_orchestrator` — es consistente y correcto.

---

## 4. Frente de Confiabilidad (Reliability)

- **Buen patrón de fallback LLM→heurística.** `execute_analyze_web_activity` captura cualquier excepción de `LLMAnalyzer.analyze_with_context` y continúa con el veredicto puramente heurístico (`raw_assessment = None` → `{}`). Esto es una fortaleza real del diseño: el sistema sigue produciendo un veredicto determinista aunque el proveedor LLM esté caído, dé timeout o devuelva JSON corrupto.
- **Sin política de reintentos (retry/backoff).** No se observa `tenacity`, backoff exponencial ni reintentos en `call_tool` (`mcp_client.py`) ni en las llamadas HTTP a los proveedores LLM. Un fallo transitorio de red (no un fallo de contenido) provoca la misma degradación a "solo heurísticas" que un fallo real del proveedor, perdiendo valor analítico innecesariamente.
- **Trazabilidad parcialmente rota por el uso de `print()`** (ver Frente 2): al no pasar por el logger estructurado, esas líneas no llevan `window_id`/`source_ip` correlacionable de forma consistente con el resto de los logs, dificultando reconstruir el flujo completo `React → FastAPI → MCP → Respuesta` ante un incidente.
- No hay *health checks* activos del `mcp_server` desde `core_orchestrator` (solo se usa `health_check()` de cada `LLMProviderInterface`, pero no se invoca periódicamente ni se expone en `/health` del core, que solo reporta `"connected"/"disconnected"` basado en si `agent_runner.agent is not None`, sin verificar viveza real de la sesión).

---

## 5. Frente de Manejo de Errores (Error Handling)

### Backend / MCP
- Los errores de validación Pydantic sí están bien manejados (`exeptions.py::validation_exception_handler` registra un handler dedicado con logging detallado de campo/motivo antes de responder 422 sin exponer trazas completas).
- El wrapper de la tool en `server.py` (`analyze_web_activity`) captura cualquier excepción y retorna un JSON con `"error": str(e)`. Ese string de excepción cruda puede propagarse hasta MongoDB (`analysis_reports`) y de ahí, dado que `AnalysisReportResponse` tiene `model_config = ConfigDict(extra="allow")`, terminar visible en el frontend del analista SOC. Riesgo de **divulgación de información interna** (rutas, nombres de módulos) — impacto moderado por tratarse de una herramienta interna, pero debería sanearse antes de persistir.
- No hay un `exception_handler` genérico para `Exception` no capturada en `main.py` (solo `RateLimitExceeded` y `RequestValidationError` están registrados); cualquier error no previsto (p. ej. desconexión de Mongo) cae al manejador por defecto de FastAPI/Starlette.

### Frontend
- Existe un único `ErrorBoundary` global (`main.tsx` envuelve toda la app). Es una buena red de seguridad contra pantallas en blanco, pero es **poco granular**: un error de renderizado en, por ejemplo, `RulesPage`, tumba el dashboard completo en lugar de degradar solo esa sección.
- Los hooks de datos (`useThreats`, `useLogs`, `useStats`) exponen `error` de forma consistente y las páginas muestran mensajes en línea (`{error ? <p>...} `) — degradación aceptable a nivel de fetch, aunque el mensaje mostrado es a veces el `Error.message` crudo devuelto por `apiFetch` (que a su vez es el body de texto de la respuesta HTTP), lo que podría filtrar mensajes de error del backend directamente al usuario final.

---

## Matriz de Hallazgos

| # | Hallazgo | Frente | Prioridad | Componente |
|---|---|---|---|---|
| 1 | API de administración de reglas (`/api/v1/rules/*`) y de ingesta de telemetría sin autenticación/autorización | Seguridad | **P1 – Crítico** | `rules_management.py`, `agent_telemetry.py`, `main.py` |
| 2 | CORS `allow_origins=["*"]` + `allow_credentials=True` | Seguridad | **P1 – Crítico** | `core_orchestrator/main.py` |
| 3 | Sesión MCP única, global, sin lock de concurrencia ni reconexión/retry | Confiabilidad/Escalabilidad | **P1 – Crítico** | `agent/mcp_client.py` |
| 4 | Canal Core↔MCP sin autenticación (confía en aislamiento de red Docker) | Seguridad | P2 – Alta | `mcp_client.py`, `server.py` |
| 5 | Endpoints de ingesta (`/ingest/*`, `/flush`) sin rate limiting → riesgo de DoS y de costo descontrolado en APIs LLM | Escalabilidad/Seguridad | P2 – Alta | `agent_telemetry.py` |
| 6 | `alert_store` en memoria de proceso — rompe correlación histórica al escalar `mcp_server` horizontalmente | Escalabilidad | P2 – Alta | `store/alert_store.py` |
| 7 | `window_manager.get_active_windows()` usa `KEYS` en vez de `SCAN`, bloqueando Redis cada 5s | Rendimiento | P2 – Alta | `services/window_manager.py`, `agent/runner.py` |
| 8 | `print()` de prompt/respuesta completos en el camino caliente del análisis (bloqueo + fuga de datos a stdout no estructurado) | Rendimiento/Confiabilidad | P2 – Alta | `mcp_servers/.../analyze_activity.py` |
| 9 | Sin política de reintentos/backoff para llamadas a MCP o a proveedores LLM ante fallos transitorios | Confiabilidad | P2 – Alta | `mcp_client.py`, `llm_providers/*` |
| 10 | Excepciones crudas (`str(exc)`) pueden persistirse en Mongo y llegar al frontend vía `extra="allow"` | Manejo de Errores | P3 – Media | `server.py`, `analysis_report.py` |
| 11 | `ErrorBoundary` único y global, poco granular | Manejo de Errores | P3 – Media | `frontend/src/main.tsx` |
| 12 | `/health` del core no verifica viveza real de la sesión MCP, solo si el objeto existe | Confiabilidad | P3 – Media | `core_orchestrator/main.py` |
| 13 | `SECRET_KEY` hardcodeada en `victim_app` (aceptable solo si se documenta como app de laboratorio) | Seguridad | P3 – Baja | `victim_app/main.py` |

---

## Top 3 Hallazgos Críticos — Código Actual vs. Propuesta Refactorizada

### 1. Ausencia de autenticación en la API de gestión de reglas y de ingesta

**Archivo actual:** `core_orchestrator/main.py`
```python
app.include_router(
    agent_telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"]
)
app.include_router(
    analytics.router,
    prefix="/api/v1",
    tags=["Analytics"]
)
app.include_router(
    rules_management.router,
    prefix="/api/v1/rules",
    tags=["Rules Management"]
)
```
Ningún router exige credenciales; `rules_management.py` expone `POST/PATCH/DELETE` sin dependencia de seguridad alguna.

**Propuesta refactorizada** — nueva dependencia de autenticación reutilizable (`core_orchestrator/security/auth.py`) aplicada a nivel de router:

```python
# core_orchestrator/security/auth.py
import os
from fastapi import Header, HTTPException, status

API_KEY = os.getenv("SENTINEL_API_KEY")  # o migrar a JWT con scopes (admin/operator/reader)

async def require_api_key(x_api_key: str = Header(default=None)):
    if not API_KEY:
        # Fail-closed: si no hay clave configurada, se rechaza en vez de abrir el sistema.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured on this server."
        )
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key."
        )
```

```python
# core_orchestrator/main.py (fragmento modificado)
from core_orchestrator.security.auth import require_api_key

app.include_router(
    agent_telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"],
    dependencies=[Depends(require_api_key)],
)
app.include_router(
    rules_management.router,
    prefix="/api/v1/rules",
    tags=["Rules Management"],
    dependencies=[Depends(require_api_key)],
)
# Para /analytics podría exponerse un rol distinto (lectura) vs. escritura (review/resolve),
# separando el router en sub-rutas read-only y write con distintas dependencias.
```
> Recomendación a mediano plazo: reemplazar la API key estática por JWT con `scopes` (`rules:write`, `telemetry:ingest`, `analytics:read`) y expiración, coherente con el resto del stack FastAPI (`fastapi.security.OAuth2PasswordBearer`), dejando la API key solo como mecanismo de *machine-to-machine* para el `log_shipper`/Filebeat.

---

### 2. CORS inseguro (`*` + credenciales)

**Archivo actual:** `core_orchestrator/main.py`
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Propuesta refactorizada:**
```python
import os

allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,      # lista explícita, nunca "*" junto a credenciales
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
```
Con `ALLOWED_ORIGINS` parametrizado vía variable de entorno (agregar a `.env.example`, `docker-compose.yml` del servicio `core`), de forma que en producción solo se permita el dominio real del `frontend`.

---

### 3. Sesión MCP única sin concurrencia segura ni reconexión

**Archivo actual:** `core_orchestrator/agent/mcp_client.py`
```python
class MCPClientManager:
    def __init__(self, server_script_path=None):
        self._session: Optional[ClientSession] = None
        ...

    async def call_tool(self, tool_name, arguments):
        if not self._session:
            raise RuntimeError("The MCP client session is not active.")
        try:
            result = await self._session.call_tool(tool_name, arguments)
            return result
        except Exception as exc:
            logger.error(...)
            return {"error": f"Exception during remote tool execution: {exc}"}
```
Una única sesión global, reutilizada por llamadas concurrentes, sin *lock* ni reconexión automática.

**Propuesta refactorizada** — serialización segura + reconexión con reintento exponencial:

```python
import asyncio
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("core_orchestrator.mcp_client")

class MCPClientManager:
    def __init__(self, server_script_path: Optional[str] = None, max_retries: int = 3):
        self.server_script_path = server_script_path
        self._transport_cm = None
        self._session_cm = None
        self._session: Optional[ClientSession] = None
        self._reconnect_lock = asyncio.Lock()   # evita reconexiones concurrentes duplicadas
        self._call_semaphore = asyncio.Semaphore(10)  # limita concurrencia real hacia el MCP server
        self._max_retries = max_retries

    async def _ensure_session(self) -> ClientSession:
        if self._session is not None:
            return self._session
        async with self._reconnect_lock:
            if self._session is None:
                logger.warning("MCP session missing, attempting reconnection...")
                await self.start_server_session()
        return self._session

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                session = await self._ensure_session()
                async with self._call_semaphore:
                    return await session.call_tool(tool_name, arguments)
            except Exception as exc:
                last_exc = exc
                logger.error(
                    "MCP call '%s' failed (attempt %d/%d): %s",
                    tool_name, attempt, self._max_retries, exc,
                )
                # Fuerza reconexión en el siguiente intento si la sesión quedó inválida.
                self._session = None
                await asyncio.sleep(min(2 ** attempt, 8))  # backoff exponencial acotado

        return {"error": f"Exception during remote tool execution after {self._max_retries} attempts: {last_exc}"}
```
Esto agrega: (a) un `Semaphore` que acota la concurrencia real hacia una sesión compartida en vez de dejarla ilimitada; (b) reconexión perezosa protegida por `Lock` cuando la sesión se pierde; (c) reintentos con backoff exponencial para fallos transitorios, evitando degradar a "solo heurísticas" ante errores de red recuperables. Para escalabilidad real a mediano plazo, se recomienda migrar a un *pool* de sesiones MCP (N sesiones) en vez de una única sesión compartida por todo el proceso.

---

## 6. Extensión: Arquitectura Multi-Cliente (Multi-Tenancy)

### 6.0 Principio de diseño

Hasta ahora el sistema asume implícitamente **un solo cliente = un solo `source_id`**. Pasar a multi-cliente no es agregar una tabla más: es introducir un **eje de aislamiento transversal** (`tenant_id`) que debe atravesar los tres componentes exactamente en los mismos puntos donde la auditoría ya identificó huecos de autenticación y de estado compartido. Es decir, **resolver el Hallazgo P1 #1 (autenticación) y el Hallazgo P2 #6 (estado en memoria del `mcp_server`) de la forma correcta ya resuelve la mitad del trabajo de multi-tenencia.**

Estrategia elegida: **esquema compartido con `tenant_id`** (una sola base MongoDB, un solo Redis, filas/documentos etiquetados) en vez de "una base de datos por cliente". Es la opción correcta para el alcance de un trabajo de grado: más simple de operar y de migrar, y perfectamente defendible si se documenta como decisión de diseño (con la puerta abierta a *DB-per-tenant* como trabajo futuro para clientes con requisitos regulatorios estrictos).

**Regla de oro que debe quedar explícita en el diseño:** el `tenant_id` **nunca se confía si viene del cliente** (body JSON, query param, header arbitrario). Siempre se deriva del mecanismo de autenticación (API key o JWT) en el servidor, y se estampa server-side antes de persistir o enrutar cualquier dato. Esto cierra, de una sola vez, un vector de *tenant spoofing* (un cliente A inyectando `tenant_id: "cliente-B"` en su payload de telemetría).

### 6.1 Modelo de datos: entidad `Tenant`

Nueva colección `tenants` (misma base `sentinel_soa`, o una base `platform` separada si se prefiere aislar metadatos de control del dato operativo):

```python
# core_orchestrator/models/tenant.py
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class Tenant(BaseModel):
    tenant_id: str                      # slug estable, ej. "acme-corp"
    display_name: str
    api_key_hash: str                   # SHA-256 de la API key; nunca se guarda en claro
    allowed_source_ids: List[str] = Field(default_factory=list)  # whitelist opcional de fuentes
    rate_limit_per_minute: int = 60     # cuota propia (fair-use / control de costo LLM)
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```

### 6.2 Identificación del tenant (evolución del Hallazgo P1 #1)

La dependencia de autenticación propuesta en la auditoría original deja de responder solo "¿es válido?" y pasa a responder "¿válido **y de qué cliente**?":

```python
# core_orchestrator/security/auth.py
import hashlib
from dataclasses import dataclass
from fastapi import Header, HTTPException, Request, status
from core_orchestrator.services.database import db


@dataclass
class TenantContext:
  tenant_id: str
  display_name: str
  rate_limit_per_minute: int


async def get_tenant_context(request: Request, x_api_key: str = Header(default=None)) -> TenantContext:
  if not x_api_key:
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header.")

  key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
  tenant_doc = await db.get_app_db().tenants.find_one({"api_key_hash": key_hash, "is_active": True})
  if not tenant_doc:
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive tenant credentials.")

  context = TenantContext(
    tenant_id=tenant_doc["tenant_id"],
    display_name=tenant_doc["display_name"],
    rate_limit_per_minute=tenant_doc.get("rate_limit_per_minute", 60),
  )
  # Se expone en request.state para que el rate limiter (slowapi) pueda usarlo como key_func.
  request.state.client_id = context.tenant_id
  return context
```

Todos los routers (`agent_telemetry`, `analytics`, `rules_management`) agregan `tenant: TenantContext = Depends(get_tenant_context)` como parámetro, y **toda** consulta/escritura queda scoped por `tenant.tenant_id`.

### 6.3 Aislamiento por componente

**a) Ingesta y ventanas de telemetría — `core_orchestrator`**

`LogEvent` gana un campo `tenant_id`, que se **sobrescribe siempre server-side** justo después de parsear, ignorando cualquier valor que venga del payload:

```python
# agent_telemetry.py (fragmento)
@router.post("/ingest/batch", status_code=202)
async def ingest_batch_events(events: List[LogEvent], tenant: TenantContext = Depends(get_tenant_context)):
  for event in events:
    event.client_id = tenant.client_id  # nunca confiar en el valor entrante
    ...
```

`WindowManager` deja de agrupar solo por IP (colisión real: dos clientes distintos pueden tener rangos privados solapados, ej. `10.0.0.5` de ambos) y agrupa por `(tenant, ip)`. Esto además resuelve el Hallazgo P2 #7 (`KEYS` → `SCAN`) en el mismo cambio:

```python
# services/window_manager.py
def get_window_key(self, log_line: LogEvent) -> str:
  return f"window:{log_line.client_id}:{log_line.source_ip}"


async def get_active_windows(self) -> List[str]:
  keys = []
  async for key in db.redis_client.scan_iter(match="window:*", count=200):
    keys.append(key)
  return keys
```

`TelemetryWindow` y el documento persistido en `analysis_reports`/`raw_telemetry` heredan el mismo `tenant_id`, y **todas** las consultas de `analytics.py` (`get_reports`, `get_stats`, `get_source_ids`) agregan `{"tenant_id": tenant.tenant_id}` al filtro — sin excepción, incluyendo el pipeline de `$facet` en `get_stats`.

**b) Reglas heurísticas — `RulesEngine` y `HeuristicRule`**

Cada cliente puede necesitar heurísticas propias (rutas sensibles distintas, umbrales distintos) sin perder una base común mantenida por el equipo de seguridad. Se modela como **baseline global + overrides por tenant**:

```python
class HeuristicRule(BaseModel):
    ...
    tenant_id: Optional[str] = None   # None/"*" = regla global aplicada a todos los tenants
```

```python
# services/rules_engine.py (firma modificada)
async def get_active_rules(self, tenant_id: str) -> RulesBundle:
    cache_key_suffix = tenant_id
    cached = await self._db.get_cached_rules(cache_key_suffix)   # cache key: rules:active:{tenant_id}
    if cached:
        return cached
    global_rules = await self._db.list_active_rules(tenant_id=None)
    tenant_rules = await self._db.list_active_rules(tenant_id=tenant_id)
    merged = rules_to_bundle(global_rules + tenant_rules, version_hash=hash_version(global_rules + tenant_rules))
    await self._db.cache_rules(merged, cache_key_suffix=cache_key_suffix)
    return merged
```

Punto de invocación en `orchestrator.py`:

```python
rules_bundle = await get_rules_engine().get_active_rules(tenant.client_id)
```

En Redis DB3, las claves pasan de `rules:active:all` a `rules:active:{tenant_id}` (más `rules:active:global` para el baseline), evitando que la caché de un cliente pise la de otro.

**c) MCP — `mcp_server` y `alert_store`**

El `alert_store` en memoria (Hallazgo P2 #6) se resuelve *y* se vuelve multi-tenant en el mismo movimiento: se migra de `threading.Lock` en memoria de proceso a Redis (compartido entre réplicas), con clave `alerts:{tenant_id}:{source_ip}`:

```python
# store/alert_store.py (esquema de clave)
def _key(self, tenant_id: str, ip: str) -> str:
    return f"alerts:{tenant_id}:{ip}"

async def add_assessment(self, tenant_id: str, ip: str, assessment: ThreatAssessment) -> None:
    await redis_client.lpush(self._key(tenant_id, ip), assessment.model_dump_json())
    await redis_client.ltrim(self._key(tenant_id, ip), 0, self._max_history - 1)

async def get_history_by_ip(self, tenant_id: str, ip: str, limit: int = 10):
    raw = await redis_client.lrange(self._key(tenant_id, ip), 0, limit - 1)
    return [ThreatAssessment.model_validate_json(r) for r in raw]
```

La tool MCP `analyze_web_activity` (`server.py`) agrega el parámetro `tenant_id: str` a su firma, y el `core_orchestrator` lo incluye siempre en `tool_arguments` (junto al `rules_bundle`, que ya viaja por request). Esto además mejora la trazabilidad: cada línea de log en el MCP puede incluir `tenant_id` y correlacionar el flujo completo `React → FastAPI → MCP` por cliente, tal como pedía el Hallazgo de Confiabilidad sobre trazabilidad.

**d) Caché de resultados de análisis**

```python
cache_key = f"cache:analysis:{tenant.client_id}:{json.dumps(telemetry_payload, sort_keys=True, default=str)}"
```
Aislamiento explícito, sin depender de que el contenido de la ventana sea suficientemente distinto entre clientes.

**e) Rate limiting por tenant (evolución del Hallazgo P2 #5)**

```python
# services/limiter.py
def tenant_or_ip_key(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None)
    return f"tenant:{tenant_id}" if tenant_id else get_remote_address(request)

limiter = Limiter(key_func=tenant_or_ip_key, storage_uri=redis_uri)
```
Con esto, la cuota se aplica **por cliente**, no por IP de origen (relevante porque varios operadores de un mismo cliente pueden compartir salida NAT), y permite además usar `tenant.rate_limit_per_minute` como límite dinámico por ruta vía `@limiter.limit(lambda request: f"{request.state.tenant_rate}/minute")` para ofrecer planes diferenciados por cliente.

**f) Frontend**

- Se agrega un flujo de autenticación mínimo (login → API key/JWT del tenant) y un `authStore` (Zustand) que guarda la identidad del tenant activo; `apiClient.ts` adjunta automáticamente `X-API-Key`/`Authorization` en cada request.
- **El frontend no necesita enviar `tenant_id` explícitamente en ninguna consulta**: el backend ya lo deriva de la credencial (mismo principio de "nunca confiar en el cliente" aplicado también en la UI). El endpoint `/analytics/source_ids` devuelve automáticamente solo los `source_id` del tenant autenticado, por lo que el selector existente en `Sidebar`/`App.tsx` sigue funcionando sin cambios de lógica, solo con datos ya pre-filtrados.
- En `RulesPage.tsx` conviene distinguir visualmente reglas heredadas (globales) vs. reglas propias del tenant (badge "Global" / "Custom"), ya que el CRUD debe seguir restringido a las reglas propias del cliente (`tenant_id == tenant.tenant_id`), nunca a las globales, salvo para un rol de operación interna con permisos elevados.

### 6.4 Plan de migración (sin downtime del dataset actual)

1. Crear la colección `tenants` con un tenant semilla (`tenant_id: "default-tenant"`) y generar su API key.
2. Agregar `tenant_id: Optional[str] = "default-tenant"` a `LogEvent`, `HeuristicRule`, y a los documentos ya persistidos en `analysis_reports` / `raw_telemetry` / `heuristic_rules` (script de backfill, análogo a `scripts/migrate_rules_to_mongodb.py`).
3. Crear índices compuestos: `db.analysis_reports.createIndex({tenant_id: 1, created_at_utc: -1})`, `db.raw_telemetry.createIndex({tenant_id: 1})`, `db.heuristic_rules.createIndex({tenant_id: 1, is_active: 1})`.
4. Desplegar la dependencia `get_tenant_context` detrás de una bandera de configuración (`ENFORCE_TENANT_AUTH=false` inicialmente) para validar el flujo sin romper el laboratorio de PoC existente, y activarla (`true`) una vez migrados los scripts de simulación (`traffic_simulator.py`, `simulate_attack_poc*.py`) para que envíen su API key de `default-tenant`.
5. Onboarding de un segundo cliente real: crear su `Tenant`, su API key, y (opcionalmente) sus reglas heurísticas propias — sin tocar código, solo datos.

### 6.5 Matriz de Hallazgos — filas añadidas

| # | Hallazgo | Frente | Prioridad | Componente |
|---|---|---|---|---|
| 14 | Sin entidad `Tenant` ni derivación server-side de identidad de cliente — requisito bloqueante para multi-tenencia | Seguridad/Arquitectura | **P1 – Crítico** | `core_orchestrator` (nuevo) |
| 15 | Claves de ventana en Redis (`window:{ip}`) y de caché de análisis colisionan entre clientes con rangos de IP privados solapados | Seguridad/Escalabilidad | P2 – Alta | `window_manager.py`, `orchestrator.py` |
| 16 | Reglas heurísticas y su caché son globales — un cliente no puede tener heurísticas propias sin afectar a los demás | Escalabilidad/Producto | P2 – Alta | `rule_schema.py`, `rules_engine.py`, `database.py` |
| 17 | Rate limiting por IP de origen en vez de por tenant — no hay cuota justa entre clientes ni control de costo LLM por cliente | Escalabilidad | P2 – Alta | `services/limiter.py` |
| 18 | Frontend sin flujo de autenticación / contexto de tenant | Seguridad | P2 – Alta | `frontend/src/lib/apiClient.ts` |

---

## Conclusión

El sistema exhibe una base de ingeniería sólida en los aspectos de resiliencia analítica (fallback LLM→heurísticas), separación de responsabilidades (Core/MCP/Frontend) y manejo de estado distribuido vía Redis para las ventanas de telemetría y el caché de reglas. Sin embargo, presenta **tres brechas críticas de seguridad y confiabilidad que deben resolverse antes de cualquier despliegue fuera de un laboratorio controlado**: ausencia total de autenticación en las APIs administrativas, configuración CORS insegura, y un canal MCP sin tolerancia a fallos ni control de concurrencia. Estos tres puntos son, además, los de mayor relevancia para la sección de "Resultados y Discusión" del trabajo de grado, dado que conectan directamente con los objetivos específicos OE3 (construcción) y OE4 (validación experimental) descritos en la propuesta de investigación.

La extensión a **arquitectura multi-cliente** (Sección 6) no es un módulo independiente sino la maduración natural del mismo hallazgo raíz: una vez que el sistema exige autenticación (Hallazgo P1 #1), esa misma credencial es el punto natural para derivar *qué cliente* está operando, y ese `tenant_id` se propaga como eje de aislamiento por los mismos puntos de código donde ya se habían detectado los hallazgos de estado compartido (`alert_store`), claves de Redis sin *namespace* (`window_manager`) y control de cuota (`rate limiter`). Esto permite presentar en la tesis una narrativa coherente: **la auditoría de seguridad no solo identifica deuda técnica, sino que define directamente la hoja de ruta arquitectónica hacia un producto multi-cliente.**