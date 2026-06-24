# Guía completa de reglas heurísticas

Esta guía documenta cómo funciona el subsistema de reglas heurísticas de Sentinel SOA, cómo crear nuevas reglas, cómo versionarlas, cómo activarlas o desactivarlas, y qué cambios son necesarios cuando se desea introducir una nueva categoría funcional.

> **Resumen corto**
>
> - La **fuente canónica inicial** de reglas es `data/mongodb/heuristic_rules.json`.
> - El **CRUD operativo** vive en MongoDB, en la base dedicada **`heuristy`**.
> - El **cache de reglas activas** vive en Redis **DB 3**.
> - El **core** arma un `RulesBundle` y lo inyecta al **MCP server**.
> - El motor `ThreatHeuristics` usa ese bundle para calcular score e indicadores.
> - Crear o editar una regla **no la activa automáticamente en el análisis**; la activación real ocurre al **activar una versión**.

---

## Tabla de contenidos

1. [Objetivo del subsistema](#objetivo-del-subsistema)
2. [Arquitectura actual](#arquitectura-actual)
3. [Componentes involucrados](#componentes-involucrados)
4. [Modelo de datos](#modelo-de-datos)
5. [Cómo se usan las reglas durante un análisis](#cómo-se-usan-las-reglas-durante-un-análisis)
6. [Caché y bases de datos](#caché-y-bases-de-datos)
7. [Catálogo de tipos y categorías soportadas](#catálogo-de-tipos-y-categorías-soportadas)
8. [CRUD de reglas](#crud-de-reglas)
9. [Versionado de reglas](#versionado-de-reglas)
10. [Activación y despliegue de versiones](#activación-y-despliegue-de-versiones)
11. [Desactivación de reglas](#desactivación-de-reglas)
12. [Validación, health y auditoría](#validación-health-y-auditoría)
13. [Cómo crear nuevas reglas](#cómo-crear-nuevas-reglas)
14. [Cómo agregar nuevas categorías](#cómo-agregar-nuevas-categorías)
15. [Bootstrap, seed y migración](#bootstrap-seed-y-migración)
16. [Variables de entorno relevantes](#variables-de-entorno-relevantes)
17. [Flujos recomendados de operación](#flujos-recomendados-de-operación)
18. [Troubleshooting](#troubleshooting)
19. [Buenas prácticas](#buenas-prácticas)
20. [Referencias de archivos clave](#referencias-de-archivos-clave)

---

## Objetivo del subsistema

El sistema de reglas heurísticas permite detectar patrones determinísticos de amenaza sin depender exclusivamente del LLM. Su propósito es:

- mantener una **línea base de scoring reproducible**;
- separar la lógica de detección del código hardcodeado;
- permitir **cambios operativos sin redeploy completo**;
- soportar **validación, auditoría y rollback**;
- alimentar al análisis del MCP con un `RulesBundle` coherente.

En términos prácticos, hoy las reglas cubren principalmente:

- detección de **User-Agents maliciosos**,
- detección de **URIs sensibles**,
- detección de **SQL Injection**,
- detección de **Path Traversal**.

---

## Arquitectura actual

### Flujo general

```text
Seed JSON / MongoDB (heuristy)
            |
            v
       RulesEngine
   (MongoDB + Redis DB3)
            |
            v
      RulesBundle activo
            |
            v
 Core Orchestrator -> tool analyze_web_activity -> MCP server
            |
            v
      ThreatHeuristics.analyze()
            |
            v
 threat_score + indicators + reasoning
```

### Idea clave

El sistema tiene **dos niveles de verdad**:

1. **Semilla canónica inicial**: `data/mongodb/heuristic_rules.json`
2. **Estado operativo activo**: MongoDB `heuristy` + versión activada + caché Redis DB3

La semilla sirve para:

- bootstrap automático,
- migración reproducible,
- fallback si el almacenamiento operativo está vacío.

El estado operativo sirve para:

- CRUD real,
- versionado,
- auditoría,
- activación de bundles productivos.

---

## Componentes involucrados

### 1. `shared/rules_seed.py`
Responsabilidades:

- cargar el seed JSON;
- extraer reglas activas;
- convertir reglas persistidas a un `bundle payload`;
- resolver el `pattern_kind` de reglas de patrones.

### 2. `core_orchestrator/models/rule_schema.py`
Define:

- `HeuristicRule`
- `HeuristicRuleUpdate`
- `RuleVersion`
- `RuleAuditLog`
- `RulesBundle`
- `hash_version()`
- `rules_to_bundle()`

### 3. `core_orchestrator/services/database.py`
Responsabilidades:

- CRUD de reglas en MongoDB;
- manejo de versiones;
- auditoría;
- caché Redis de reglas activas.

### 4. `core_orchestrator/services/rules_engine.py`
Responsabilidades:

- cargar reglas activas desde caché, Mongo o fallback;
- bootstrap inicial si la BD de reglas está vacía;
- activar versiones;
- reconstruir y cachear el `RulesBundle`.

### 5. `core_orchestrator/services/rule_validator.py`
Responsabilidades:

- validar reglas individualmente;
- validar bundles completos;
- ejecutar casos de prueba mínimos antes de activar reglas.

### 6. `core_orchestrator/api/v1/endpoints/rules_management.py`
Expone la API REST de administración.

### 7. `core_orchestrator/agent/orchestrator.py`
Responsabilidades:

- obtener el `RulesBundle` activo;
- inyectarlo en la llamada MCP a `analyze_web_activity`.

### 8. `mcp_servers/log_analysis_server/services/heuristics_engine.py`
Responsabilidades:

- usar el `RulesBundle` recibido;
- calcular score e indicadores determinísticos.

---

## Modelo de datos

## `HeuristicRule`

Representa una regla persistida en MongoDB.

Campos principales:

- `rule_id`: identificador único lógico.
- `rule_type`: tipo de regla.
- `category`: dominio funcional de la regla.
- `version`: versión de la regla individual.
- `is_active`: si participa o no en el bundle activo al construirlo.
- `description`: descripción humana.
- `content`: datos operativos de la regla.
- `metadata`: metadatos de cambio.
- `validation_rules`: reglas declarativas de validación.
- `created_at`, `updated_at`: timestamps.

### Estructura de `content`

```json
{
  "type": "keyword_mapping",
  "data": {
    "sqlmap": 35,
    "nikto": 30
  },
  "match_strategy": "substring_case_insensitive"
}
```

### Tipos de `content.data` hoy usados

#### `keyword_mapping`
Mapa `clave -> score`.

Ejemplos:

- `user_agent`: `{"sqlmap": 35, "nikto": 30}`
- `uri`: `{"/.env": 40, "/etc/passwd": 45}`

#### `pattern_list`
Lista de patrones + score por match.

```json
{
  "patterns": ["' OR 1=1", "UNION SELECT"],
  "pattern_kind": "sql_injection",
  "score_per_match": 30
}
```

> `pattern_kind` es importante para evitar depender del prefijo de `rule_id`.

---

## `RuleVersion`

Agrupa un conjunto de `rule_id` para desplegar un bundle concreto.

Campos principales:

- `version_hash`
- `created_at`
- `is_active`
- `rules_included`
- `changelog`
- `deployed_by`
- `deployment_timestamp`
- `rollback_url`

### Importante

Una versión **no copia el contenido completo** de las reglas; solo referencia `rule_id`s. Cuando se activa una versión, el sistema vuelve a leer esas reglas y reconstruye el bundle.

---

## `RuleAuditLog`

Registra quién hizo qué, cuándo y sobre cuál regla o versión.

Campos principales:

- `timestamp`
- `action` (`CREATE`, `UPDATE`, `DELETE`, `ACTIVATE`, `ROLLBACK`)
- `rule_id`
- `user`
- `ip_address`
- `changes.before`
- `changes.after`
- `reason`
- `status`

---

## `RulesBundle`

Es la estructura que realmente consume el motor heurístico.

Hoy contiene:

```json
{
  "malicious_ua_keywords": {},
  "sensitive_uris": {},
  "sql_injection_patterns": [],
  "path_traversal_patterns": [],
  "sql_injection_score": 30,
  "path_traversal_score": 40,
  "version_hash": "v1_initial_migrated_rules",
  "last_updated": "2026-06-23T10:00:00+00:00"
}
```

### Observación importante

Aunque el esquema admite `category="threshold"`, el `RulesBundle` actual **no incorpora thresholds genéricos adicionales**. Si quieres que una nueva categoría afecte el score en tiempo de ejecución, debes extender el bundle y el motor heurístico.

---

## Cómo se usan las reglas durante un análisis

Cuando el core procesa una ventana de telemetría:

1. `OrchestratorAgent` obtiene el bundle activo con `get_rules_engine().get_active_rules()`.
2. Ese bundle se serializa con `to_cache_dict()`.
3. El core llama al tool MCP `analyze_web_activity` y envía `rules_bundle`.
4. En el MCP, `execute_analyze_web_activity()` reconstruye el bundle.
5. `ThreatHeuristics.analyze()` usa ese bundle para:
   - revisar User-Agents,
   - revisar URIs sensibles,
   - revisar response codes,
   - revisar RPS,
   - revisar métodos HTTP,
   - revisar patrones de inyección.

### Orden lógico del análisis heurístico

El motor actual evalúa:

1. User-Agents
2. URIs sensibles
3. anomalías por códigos HTTP
4. RPS
5. métodos HTTP sospechosos
6. SQL Injection y Path Traversal

### Qué partes son dinámicas y cuáles no

**Dinámicas por reglas**:

- `malicious_ua_keywords`
- `sensitive_uris`
- `sql_injection_patterns`
- `path_traversal_patterns`
- `sql_injection_score`
- `path_traversal_score`

**Fijas en código hoy**:

- scoring por ratio 404,
- scoring por 5xx,
- scoring por 403,
- scoring por RPS,
- scoring por métodos HTTP.

Si necesitas parametrizar esas últimas, eso ya requiere extender el modelo actual.

---

## Caché y bases de datos

## MongoDB

### Base de aplicación

- nombre por defecto: `sentinel_soa`
- contiene datos operativos como telemetría y reportes.

### Base de reglas

- nombre por defecto: `heuristy`
- contiene:
  - `heuristic_rules`
  - `rule_versions`
  - `rule_audit_log`

## Redis

### Redis DB de aplicación

- DB `0` para otros flujos generales.

### Redis DB de reglas

- DB `3` por defecto (`REDIS_RULES_DB`)

Claves:

- `rules:active:all`
- `rules:metadata:version_hash`
- `rules:metadata:last_updated`

TTL por defecto:

- `RULES_CACHE_TTL_SECONDS=86400` (24 horas)

### Estrategia de lectura

`RulesEngine.get_active_rules()` sigue este orden:

1. Redis DB3
2. MongoDB `heuristy`
3. seed/fallback

### Estrategia de invalidación

- Al activar una versión se invalida el caché.
- Luego se reconstruye el bundle y se vuelve a cachear.

---

## Catálogo de tipos y categorías soportadas

## Tipos (`rule_type`)

### 1. `keyword_mapping`
Usado para diccionarios `texto -> score`.

### 2. `pattern_list`
Usado para listas de patrones.

### 3. `threshold`
Está admitido en el esquema, pero **hoy no tiene mapeo completo al `RulesBundle` ni uso operativo en `ThreatHeuristics`**.

---

## Categorías (`category`)

### 1. `user_agent`
Se mapea a `RulesBundle.malicious_ua_keywords`.

### 2. `uri`
Se mapea a `RulesBundle.sensitive_uris`.

### 3. `injection`
Se usa con `pattern_list` y se distingue por `pattern_kind`:

- `sql_injection`
- `path_traversal`

### 4. `threshold`
Existe en el esquema pero no está operativamente conectado al motor actual.

---

## CRUD de reglas

Base path:

```text
/api/v1/rules
```

## 1. Listar reglas

```bash
curl http://localhost:8000/api/v1/rules
```

Incluir inactivas:

```bash
curl "http://localhost:8000/api/v1/rules?include_inactive=true"
```

Respuesta esperada:

```json
{
  "rules": [...],
  "version_hash": "v1_initial_migrated_rules",
  "total": 4
}
```

## 2. Obtener una regla

```bash
curl http://localhost:8000/api/v1/rules/malicious_ua_keywords_v1
```

## 3. Crear una regla

```bash
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d @new_rule.json
```

## 4. Actualizar una regla

```bash
curl -X PATCH http://localhost:8000/api/v1/rules/malicious_ua_keywords_v1 \
  -H "Content-Type: application/json" \
  -d '{
    "description": "UA maliciosos actualizados",
    "metadata": {
      "source": "admin_dashboard",
      "changed_by": "security@company.com",
      "change_reason": "Agregadas nuevas firmas",
      "compatibility_version": "1.0.0"
    }
  }'
```

## 5. Desactivar una regla

```bash
curl -X DELETE "http://localhost:8000/api/v1/rules/malicious_ua_keywords_v1?user=security@company.com&reason=Deprecated"
```

### Importante sobre el CRUD

- El CRUD modifica documentos en `heuristic_rules`.
- **No crea ni activa automáticamente una nueva versión**.
- Para que el bundle de análisis use un conjunto controlado de reglas, debes crear y activar una versión.

---

## Versionado de reglas

Endpoints relevantes:

- `GET /api/v1/rules/versions`
- `GET /api/v1/rules/versions/{version_hash}`
- `POST /api/v1/rules/versions`

## Crear una versión

```bash
curl -X POST http://localhost:8000/api/v1/rules/versions \
  -H "Content-Type: application/json" \
  -d '{
    "rules_included": [
      "malicious_ua_keywords_v1",
      "sensitive_uris_v1",
      "sql_injection_patterns_v1",
      "path_traversal_patterns_v1"
    ],
    "changelog": "Bundle base SOC",
    "deployed_by": "security@company.com"
  }'
```

### Qué valida el backend al crear la versión

1. que todas las reglas existan;
2. que el bundle sea válido según `RuleValidator.validate_rules()`;
3. que pasen los test patterns internos.

### Cómo se genera `version_hash`

El backend usa `hash_version(rules)`.

**Importante**: el hash actual se calcula con una tupla ordenada de:

- `rule_id`
- `version`
- `category`

Eso significa que **cambiar solo la descripción o metadata no altera el hash**, mientras que cambiar `version` sí lo hace.

Recomendación operativa: cuando una regla cambie de forma significativa, incrementa también su campo `version`.

---

## Activación y despliegue de versiones

La activación real ocurre con:

```text
POST /api/v1/rules/versions/activate/{version_hash}
```

Ejemplo:

```bash
curl -X POST http://localhost:8000/api/v1/rules/versions/activate/v1_initial_migrated_rules
```

## Qué pasa internamente al activar

`RulesEngine.deploy_version()` hace:

1. busca la versión;
2. carga las reglas incluidas por `rule_id`;
3. valida que existan todas;
4. valida bundle y tests mínimos;
5. desmarca otras versiones activas;
6. marca esta versión como activa;
7. invalida Redis DB3;
8. reconstruye el `RulesBundle`;
9. cachea el nuevo bundle;
10. deja ese bundle listo para el core y el MCP.

## Qué NO hace la activación

- no cambia automáticamente el seed JSON;
- no edita el snapshot salvo que ejecutes migración/script correspondiente;
- no recrea reglas faltantes por sí sola.

---

## Desactivación de reglas

Desactivar una regla (`DELETE /api/v1/rules/{rule_id}`) hace un **soft delete**:

- no borra el documento;
- cambia `is_active = false`;
- actualiza `updated_at`.

### Consideración importante

Si una versión activa sigue refiriéndose a una regla que luego fue desactivada, el comportamiento operativo depende del momento en que reconstruyas el bundle:

- el bundle solo incorpora reglas con `is_active=true`;
- una versión que apunte a reglas desactivadas puede producir un bundle incompleto o fallar validaciones al reactivarse/reconstruirse.

Recomendación:

1. crear una nueva versión sin la regla,
2. activarla,
3. luego desactivar la regla antigua si ya no debe usarse.

---

## Validación, health y auditoría

## Validar un conjunto de reglas

```bash
curl -X POST http://localhost:8000/api/v1/rules/validate \
  -H "Content-Type: application/json" \
  -d '{"rules": [...]}'
```

La validación incluye:

- consistencia entre `rule_type` y `content.type`;
- compilación regex si aplica;
- bundle con al menos una regla activa;
- advertencia por categorías faltantes;
- test cases internos:
  - `nikto_user_agent`
  - `sql_injection_uri`
  - `path_traversal_uri`
  - `sensitive_uri`

## Health del motor de reglas

```bash
curl http://localhost:8000/api/v1/rules/health
```

Respuesta esperada:

```json
{
  "status": "healthy",
  "cached": true,
  "version_hash": "v1_initial_migrated_rules",
  "last_updated": "2026-06-23T10:00:00+00:00",
  "source": "cache",
  "total_active_rules": 4
}
```

Valores posibles de `source`:

- `cache`
- `mongodb`
- `fallback`

## Auditoría

```bash
curl http://localhost:8000/api/v1/rules/audit-log
```

Filtrar por regla:

```bash
curl "http://localhost:8000/api/v1/rules/audit-log?rule_id=malicious_ua_keywords_v1&limit=20"
```

---

## Cómo crear nuevas reglas

## Caso 1: nueva regla de User-Agent

Usa:

- `rule_type = keyword_mapping`
- `category = user_agent`

Ejemplo:

```json
{
  "rule_id": "malicious_ua_keywords_v2",
  "rule_type": "keyword_mapping",
  "category": "user_agent",
  "version": 2,
  "is_active": true,
  "description": "Nuevas firmas de herramientas de escaneo en UA",
  "content": {
    "type": "keyword_mapping",
    "data": {
      "gobuster": 22,
      "masscan": 20,
      "nuclei": 25
    },
    "match_strategy": "substring_case_insensitive"
  },
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security@company.com",
    "change_reason": "Se agregan nuevas firmas de escaneo",
    "compatibility_version": "1.0.0"
  },
  "validation_rules": {
    "min_score": 0,
    "max_score": 100,
    "required_fields": ["rule_id", "category"]
  },
  "created_at": "2026-06-24T15:00:00Z",
  "updated_at": "2026-06-24T15:00:00Z"
}
```

---

## Caso 2: nueva regla de URI sensible

Usa:

- `rule_type = keyword_mapping`
- `category = uri`

Ejemplo:

```json
{
  "rule_id": "sensitive_uris_v2",
  "rule_type": "keyword_mapping",
  "category": "uri",
  "version": 2,
  "is_active": true,
  "description": "Rutas sensibles adicionales",
  "content": {
    "type": "keyword_mapping",
    "data": {
      "/internal": 20,
      "/debug": 25,
      "/actuator/heapdump": 45
    },
    "match_strategy": "substring_case_insensitive"
  },
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security@company.com",
    "change_reason": "Se agregan endpoints de debug expuestos",
    "compatibility_version": "1.0.0"
  },
  "validation_rules": {
    "min_score": 0,
    "max_score": 100,
    "required_fields": ["rule_id", "category"]
  },
  "created_at": "2026-06-24T15:00:00Z",
  "updated_at": "2026-06-24T15:00:00Z"
}
```

---

## Caso 3: nueva regla de SQL Injection

Usa:

- `rule_type = pattern_list`
- `category = injection`
- `content.data.pattern_kind = sql_injection`

Ejemplo:

```json
{
  "rule_id": "sql_injection_patterns_v2",
  "rule_type": "pattern_list",
  "category": "injection",
  "version": 2,
  "is_active": true,
  "description": "Firmas adicionales de SQLi",
  "content": {
    "type": "pattern_list",
    "data": {
      "patterns": [
        "OR SLEEP(",
        "UNION ALL SELECT",
        "information_schema"
      ],
      "pattern_kind": "sql_injection",
      "score_per_match": 35
    },
    "match_strategy": "substring_case_insensitive"
  },
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security@company.com",
    "change_reason": "Expansión de payloads SQLi",
    "compatibility_version": "1.0.0"
  },
  "validation_rules": {
    "min_score": 0,
    "max_score": 100,
    "required_fields": ["rule_id", "category"]
  },
  "created_at": "2026-06-24T15:00:00Z",
  "updated_at": "2026-06-24T15:00:00Z"
}
```

---

## Caso 4: nueva regla de Path Traversal

Usa:

- `rule_type = pattern_list`
- `category = injection`
- `content.data.pattern_kind = path_traversal`

Ejemplo:

```json
{
  "rule_id": "path_traversal_patterns_v2",
  "rule_type": "pattern_list",
  "category": "injection",
  "version": 2,
  "is_active": true,
  "description": "Variantes adicionales de traversal",
  "content": {
    "type": "pattern_list",
    "data": {
      "patterns": [
        "..%255c",
        "..%c1%9c",
        "..%2f..%2f"
      ],
      "pattern_kind": "path_traversal",
      "score_per_match": 45
    },
    "match_strategy": "substring_case_insensitive"
  },
  "metadata": {
    "source": "admin_dashboard",
    "changed_by": "security@company.com",
    "change_reason": "Cobertura de traversal multi-encoding",
    "compatibility_version": "1.0.0"
  },
  "validation_rules": {
    "min_score": 0,
    "max_score": 100,
    "required_fields": ["rule_id", "category"]
  },
  "created_at": "2026-06-24T15:00:00Z",
  "updated_at": "2026-06-24T15:00:00Z"
}
```

---

## Flujo recomendado para introducir una nueva regla

1. definir el JSON;
2. ejecutar `POST /api/v1/rules/validate` con el bundle esperado;
3. crear la regla con `POST /api/v1/rules`;
4. crear una versión con los `rule_id` deseados;
5. activar la versión;
6. revisar `GET /api/v1/rules/health`;
7. revisar `GET /api/v1/rules/audit-log`.

---

## Cómo agregar nuevas categorías

Agregar una nueva regla dentro de una categoría existente es simple.

Agregar una **nueva categoría funcional** requiere cambios de código, porque el bundle actual y el motor heurístico conocen un conjunto fijo de categorías útiles.

## Diferencia importante

### A. Nueva regla en categoría existente
Ejemplo: otra regla `user_agent`.

- normalmente **no requiere tocar código**;
- basta con crear regla + versión + activar.

### B. Nueva categoría operativa
Ejemplo: `header`, `cookie`, `body_pattern`, `authentication_behavior`.

- **sí requiere tocar código**.

---

## Cambios mínimos para agregar una nueva categoría operativa

### 1. Extender el esquema
Archivo:

- `core_orchestrator/models/rule_schema.py`

Acciones típicas:

- agregar la nueva categoría al `Literal` `RuleCategory`;
- si hace falta, agregar nuevos campos al `RulesBundle`.

Ejemplo conceptual:

```python
RuleCategory = Literal["user_agent", "uri", "injection", "threshold", "header"]
```

Y en `RulesBundle`:

```python
header_keywords: Dict[str, int] = field(default_factory=dict)
```

---

### 2. Mapear la categoría al bundle
Archivo:

- `shared/rules_seed.py`

Debes extender `build_bundle_payload_from_rules()` para que convierta esa categoría en una estructura concreta dentro del bundle.

Ejemplo conceptual:

```python
if rule_type == "keyword_mapping" and category == "header":
    bundle["header_keywords"].update({k: int(v) for k, v in data.items()})
```

---

### 3. Extender el bundle del MCP
Archivo:

- `mcp_servers/log_analysis_server/models/rules_bundle.py`

Debe reflejar los nuevos campos del bundle para que el MCP pueda reconstruirlo correctamente.

---

### 4. Consumir la categoría en el motor heurístico
Archivo:

- `mcp_servers/log_analysis_server/services/heuristics_engine.py`

Tareas típicas:

- crear un nuevo método de análisis, por ejemplo `_analyze_headers()`;
- sumarlo dentro de `ThreatHeuristics.analyze()`;
- producir score, indicadores y reasoning.

---

### 5. Ajustar la validación
Archivo:

- `core_orchestrator/services/rule_validator.py`

Debes decidir:

- qué estructura debe tener `content.data`;
- qué warnings/errores aplicar;
- qué test cases mínimos deben cubrir la categoría.

---

### 6. Extender ejemplos seed y frontend
Archivos probables:

- `data/mongodb/heuristic_rules.json`
- `frontend/src/types/rules.ts`
- `frontend/src/features/rules/RulesPage.tsx`

---

### 7. Agregar pruebas
Se recomienda cubrir:

- validación de esquema;
- transformación a bundle;
- uso en `ThreatHeuristics`;
- activación de versión;
- UI si la categoría se administra desde frontend.

---

## Ejemplo de categoría nueva: `header`

Si quieres detectar headers sospechosos:

1. agregas `header` a `RuleCategory`;
2. agregas `header_keywords` a `RulesBundle`;
3. mapeas esa categoría en `shared/rules_seed.py`;
4. amplías `AnalysisInput` para incluir headers agregados si aún no existen;
5. creas `_analyze_headers()` en `ThreatHeuristics`;
6. agregas tests y ejemplos de seed.

Sin esos cambios, una regla `category="header"` podría persistirse, pero **no tendría impacto real en el análisis**.

---

## Bootstrap, seed y migración

## Bootstrap automático

Si `RulesEngine` intenta cargar reglas activas y MongoDB `heuristy` está vacío:

1. carga `data/mongodb/heuristic_rules.json`;
2. inserta reglas, versiones y auditoría;
3. crea el bundle;
4. lo cachea en Redis DB3.

Eso ocurre en `RulesEngine._seed_rules_store_if_empty()`.

## Script de migración

Archivo:

- `scripts/migrate_rules_to_mongodb.py`

Uso:

```bash
python scripts/migrate_rules_to_mongodb.py
python scripts/migrate_rules_to_mongodb.py --dry-run
python scripts/migrate_rules_to_mongodb.py --force
```

### Qué hace el script

- lee el seed JSON;
- valida y construye objetos Pydantic;
- inserta reglas, versiones y auditoría en MongoDB;
- calienta Redis DB3;
- escribe snapshot de bundle en `data/mongodb/heuristic_rules_bundle.json`;
- escribe reporte en `data/mongodb/migration_report.json`.

### Cuándo usarlo

- bootstrap manual reproducible;
- recreación de entorno;
- staging o recovery;
- regeneración inicial después de limpiar `heuristy`.

---

## Variables de entorno relevantes

| Variable | Propósito | Default |
|---|---|---|
| `MONGO_DB_NAME` | base Mongo de aplicación | `sentinel_soa` |
| `RULES_MONGO_DB_NAME` | base Mongo dedicada a reglas | `heuristy` |
| `REDIS_RULES_DB` | DB de Redis para reglas | `3` |
| `RULES_CACHE_TTL_SECONDS` | TTL del bundle cacheado | `86400` |
| `MONGO_HOST` | host MongoDB | `mongo` |
| `MONGO_PORT` | puerto MongoDB | `27017` |
| `REDIS_HOST` | host Redis | `redis` |
| `REDIS_PORT` | puerto Redis | `6379` |

---

## Flujos recomendados de operación

## Escenario 1: agregar una firma nueva sin romper producción

1. duplicar la regla base e incrementar `version`;
2. agregar nuevos valores a `content.data`;
3. validar bundle;
4. crear versión nueva;
5. activar versión nueva;
6. revisar health;
7. revisar auditoría.

## Escenario 2: retirar una regla obsoleta

1. crear nueva versión sin esa regla;
2. activar nueva versión;
3. verificar que el bundle activo quedó correcto;
4. desactivar la regla vieja.

## Escenario 3: disaster recovery

1. verificar si `heuristy` está vacía;
2. usar bootstrap automático o `scripts/migrate_rules_to_mongodb.py --force`;
3. revisar `rules/health`;
4. revisar `migration_report.json`.

---

## Troubleshooting

## Problema: la regla existe pero no impacta el score

Posibles causas:

- no está incluida en la versión activa;
- la versión activa no fue redeployada;
- `is_active=false`;
- la categoría no está mapeada al bundle;
- `pattern_kind` faltante o incorrecto;
- el campo existe en Mongo pero no en el `RulesBundle` del MCP.

Checklist:

1. `GET /api/v1/rules/{rule_id}`
2. `GET /api/v1/rules/versions`
3. `GET /api/v1/rules/health`
4. revisar Redis DB3 / logs de `RulesEngine`
5. revisar si `ThreatHeuristics` consume esa estructura

## Problema: una versión no activa

Posibles causas:

- faltan reglas de `rules_included`;
- falló `RuleValidator.validate_rules()`;
- hay tests internos fallando;
- una regla quedó inactiva y el bundle ya no es coherente.

## Problema: el bundle vuelve al fallback

Posibles causas:

- falla de MongoDB;
- falla al leer caché y luego falla Mongo;
- seed/fallback disponible y motor lo usa como respaldo.

## Problema: se crea una regla pero el `version_hash` no cambia

Esto puede ser esperado si:

- no incrementaste `version`;
- solo cambiaste metadata o descripción;
- aún no creaste/activaste una nueva versión.

---

## Buenas prácticas

1. **Incrementa `version` de la regla** cuando el comportamiento cambie realmente.
2. **No edites producción “en caliente” sin crear versión**.
3. **Usa `pattern_kind` explícito** para reglas de `pattern_list`.
4. **No desactives primero y arregles después**; crea una versión nueva antes.
5. **Documenta `change_reason`** de forma clara; la auditoría depende de eso.
6. **Mantén ejemplos y seed actualizados** si el cambio debe ser reproducible en nuevos entornos.
7. **Agrega tests** cuando introduzcas una categoría nueva.
8. **Verifica `rules/health` después de cada activación**.
9. **No asumas que `threshold` ya está operativo**: hoy necesita extensión adicional para tener efecto real.
10. **Sincroniza frontend, API, schema y MCP** cuando cambies el contrato del bundle.

---

## Referencias de archivos clave

### Backend / Core

- `core_orchestrator/models/rule_schema.py`
- `core_orchestrator/services/database.py`
- `core_orchestrator/services/rules_engine.py`
- `core_orchestrator/services/rule_validator.py`
- `core_orchestrator/api/v1/endpoints/rules_management.py`
- `core_orchestrator/agent/orchestrator.py`

### MCP

- `mcp_servers/log_analysis_server/services/heuristics_engine.py`
- `mcp_servers/log_analysis_server/tools/analyze_activity.py`
- `mcp_servers/log_analysis_server/models/rules_bundle.py`

### Shared / Data / Scripts

- `shared/rules_seed.py`
- `data/mongodb/heuristic_rules.json`
- `data/mongodb/heuristic_rules_bundle.json`
- `scripts/migrate_rules_to_mongodb.py`

### Frontend

- `frontend/src/features/rules/RulesPage.tsx`
- `frontend/src/lib/rulesApi.ts`
- `frontend/src/types/rules.ts`

---

## Nota final

El modelo actual ya resuelve el problema principal de sacar reglas hardcodeadas del análisis principal y convertirlas en una capacidad administrable. Sin embargo, la extensibilidad real depende de entender esta regla de oro:

> **Persistir una regla nueva no implica automáticamente que el motor heurístico sepa usarla.**
>
> Si la regla pertenece a una categoría ya soportada por el `RulesBundle`, normalmente bastará con CRUD + versión + activación. Si introduces una categoría nueva, debes extender también el bundle, la transformación y el motor de análisis.

