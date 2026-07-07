# Plan ejecutable de refactorización hexagonal para `core_orchestrator`

## Objetivo
Dejar `core_orchestrator` alineado al 100% con Arquitectura Hexagonal + DDD:
- `domain` puro, sin dependencias técnicas.
- `application` solo usa puertos del `domain`.
- `infrastructure` contiene toda la implementación concreta.
- Cada modulo vertical queda aislado y testeable.

## Diagnóstico resumido
### Violaciones actuales a corregir primero
- `application/modules/auth_clients/services/user_service.py` importa `infrastructure.security.password.verify_password`.
- `application/modules/auth_clients/services/auth_service.py` importa `infrastructure.config.config.orchestrator_settings` y `infrastructure.security.jwt_utils`.
- `application/modules/auth_clients/services/telemetry_client_service.py` importa `infrastructure.security.jwt_utils.verify_hmac_signature`.
- `application/modules/analysis_reports/services/analysis_service.py` importa `infrastructure.agent.mcp_client.MCPClientManager`.
- `application/modules/analysis_reports/services/threat_context_service.py` importa `infrastructure.agent.mcp_client.MCPClientManager`.
- `application/modules/telemetry/services/telemetry_processing_service.py` importa `infrastructure.config.config.orchestrator_settings`.
- `application/modules/analysis_reports/services/rules_engine_service.py` contiene singleton global (`init_rules_engine`, `get_rules_engine`).

### Lo que ya está bien
- Los repositorios concretos viven en `infrastructure/persistence` o `infrastructure/cache`.
- La mayor parte de los puertos está en `domain/ports`.
- El contenedor centraliza el wiring de dependencias.

---

## Regla de trabajo para este plan
1. No mover lógica de negocio a `infrastructure`.
2. No importar `infrastructure` desde `application`.
3. Todo detalle técnico debe entrar por un puerto.
4. Todo cambio debe incluir prueba unitaria o verificación arquitectónica.
5. Hacer cambios por fase, sin mezclar objetivos.

---

# Fase 0. Inventario y base de seguridad
## Meta
Tener visibilidad completa antes de tocar código.

## Tareas
- [ ] Listar imports prohibidos en `core_orchestrator/application/**/*.py`.
- [ ] Confirmar puertos existentes en `core_orchestrator/domain/ports`.
- [ ] Identificar dependencias entre módulos de `application/modules/*`.
- [ ] Identificar endpoints que usan singletons o accesos globales.

## Entregable
Un mapa breve con:
- archivo
- problema
- severidad
- acción sugerida

---

# Fase 1. Cortar dependencias directas Application -> Infrastructure
## Meta
Eliminar imports técnicos desde casos de uso.

## 1.1 Password hashing
### Estado actual
`user_service.py` llama directamente a `verify_password`.

### Acción
- Crear `domain/ports/password_hasher.py`.
- Crear adaptador en `infrastructure/security/`.
- Inyectar el puerto en `UserService`.

### Archivo objetivo
- `core_orchestrator/application/modules/auth_clients/services/user_service.py`

### Criterio de aceptación
- `user_service.py` no importa nada de `infrastructure`.
- `authenticate_user()` usa solo `PasswordHasherPort`.

## 1.2 JWT y logout
### Estado actual
`auth_service.py` usa `orchestrator_settings` y `jwt_utils`.

### Acción
- Crear `domain/ports/token_service.py` o separar en:
  - `TokenIssuerPort`
  - `TokenParserPort`
- Mover `create_access_token` y `get_token_jti` a infraestructura.
- Inyectar TTL/configuración como valor simple o value object.

### Archivo objetivo
- `core_orchestrator/application/modules/auth_clients/services/auth_service.py`

### Criterio de aceptación
- `auth_service.py` no importa `infrastructure.*`.
- El TTL del token entra por constructor, no por import global.

## 1.3 Verificación HMAC de telemetry clients
### Estado actual
`telemetry_client_service.py` usa `verify_hmac_signature` directo.

### Acción
- Crear `domain/ports/signature_verifier.py`.
- Implementar adaptador en `infrastructure/security/`.
- Inyectar el verificador en `TelemetryClientService`.

### Archivo objetivo
- `core_orchestrator/application/modules/auth_clients/services/telemetry_client_service.py`

### Criterio de aceptación
- El servicio no importa `infrastructure.security.jwt_utils`.

## 1.4 Configuración de telemetry
### Estado actual
`telemetry_processing_service.py` lee `orchestrator_settings`.

### Acción
- Crear un value object de configuración, por ejemplo `TelemetryWindowPolicy`.
- Inyectar duración y umbral en el constructor.
- El contenedor traduce `orchestrator_settings` a valores simples.

### Archivo objetivo
- `core_orchestrator/application/modules/telemetry/services/telemetry_processing_service.py`

### Criterio de aceptación
- No hay imports de `infrastructure.config` en esa capa.

---

# Fase 2. Desacoplar MCP y LLM de la capa de aplicación
## Meta
Reemplazar `MCPClientManager` por puertos.

## 2.1 Crear puertos de análisis
### Puertos sugeridos
- `domain/ports/llm_analysis_port.py`
- `domain/ports/threat_context_port.py`

### Responsabilidad
- Exponer operaciones de análisis y contexto histórico sin mencionar MCP.

## 2.2 Crear adapters concretos
### Ubicación
- `infrastructure/agent/mcp_llm_analysis_adapter.py`
- `infrastructure/agent/mcp_threat_context_adapter.py`

### Responsabilidad
- Traducir llamadas de puerto a `MCPClientManager`.

## 2.3 Refactor de casos de uso
### Archivos
- `application/modules/analysis_reports/services/analysis_service.py`
- `application/modules/analysis_reports/services/threat_context_service.py`

### Acción
- Reemplazar `MCPClientManager` por puertos.
- Mantener la normalización/sanitización dentro de `application`.
- Dejar parsing JSON/resultado MCP dentro del adapter si es posible.

### Criterio de aceptación
- `application/modules/analysis_reports/services/*` no importa `infrastructure.agent.*`.

---

# Fase 3. Eliminar singleton y dependencias globales
## Meta
Hacer que el contenedor sea la única fuente de instancias.

## 3.1 Quitar singleton de rules engine
### Archivo
- `core_orchestrator/application/modules/analysis_reports/services/rules_engine_service.py`

### Acción
- Eliminar:
  - `_rules_engine_instance`
  - `init_rules_engine()`
  - `get_rules_engine()`
- Dejar solo la clase `RulesEngineService`.
- Inicializar siempre desde `infrastructure/api/container.py`.

### 3.2 Ajustar endpoints
### Archivo probable
- `core_orchestrator/infrastructure/api/v1/endpoints/rules.py`

### Acción
- Mantener `Depends(get_rules_engine_service)`.
- Eliminar cualquier acceso global directo si existe en otros endpoints.

### Criterio de aceptación
- No quedan accesos globales al rules engine.
- Todos los tests usan inyección explícita.

---

# Fase 4. Corregir frontera entre application y persistence
## Meta
Evitar que los casos de uso absorban detalles de Mongo/Pydantic de infraestructura.

## 4.1 Revisar `AnalyticsService`
### Archivo
- `core_orchestrator/application/modules/analysis_reports/services/analytics_service.py`

### Acción
- Revisar si `ObjectId` y conversiones de documento deben moverse al repositorio/adaptador.
- Preferir que `application` trabaje con modelos del dominio o DTOs estables.
- Reducir lógica de adaptación de documentos a lo mínimo.

### Criterio de aceptación
- `application` no depende de tipos de persistencia innecesarios.

## 4.2 Revisar puertos que aceptan `BaseModel`
### Archivos
- `domain/ports/analytics_service_port.py`
- `domain/ports/analytics_repository.py`

### Acción
- Si el tipo expone demasiado `pydantic.BaseModel`, evaluar DTOs propios del dominio.
- Solo mantener `BaseModel` si realmente representa el contrato del dominio y no un detalle técnico.

---

# Fase 5. Endurecer aislamiento entre módulos
## Meta
Asegurar rebanado vertical real.

## Reglas objetivo
- `auth_clients` no importa `analysis_reports` ni `telemetry`.
- `telemetry` no importa `analysis_reports` salvo por puertos/casos de uso explícitos.
- `analysis_reports` no depende de implementaciones de otros módulos.
- Si un modulo necesita otro, debe hacerlo a traves de puerto o caso de uso orquestado en `container.py`.

## Acciones
- [ ] Revisar imports entre `application/modules/*`.
- [ ] Revisar que `container.py` sea el unico lugar de composicion.
- [ ] Si aparece dependencia transversal, extraer un puerto compartido.

---

# Fase 6. Verificacion y pruebas
## Pruebas minimas por fase
### Unitarias
- `UserService` con mock de `PasswordHasherPort`.
- `AuthService` con mock de token service.
- `TelemetryClientService` con mock de signature verifier.
- `AnalysisService` con mock de puerto MCP.
- `TelemetryProcessingService` con config inyectada.
- `RulesEngineService` sin singleton.

### Arquitectura
- Regla: `application` no importa `infrastructure`.
- Regla: `domain` no importa `application` ni `infrastructure`.
- Regla: no usar singletons globales en casos de uso.

### Criterio de cierre
- Ninguna importación prohibida detectada en `core_orchestrator/application/**/*.py`.
- Todos los servicios de aplicación dependen solo de puertos o value objects.
- El contenedor construye todas las dependencias concretas.

---

# Orden de ejecución recomendado
1. Fase 1.1 y 1.2
2. Fase 1.3 y 1.4
3. Fase 2 completa
4. Fase 3 completa
5. Fase 4 completa
6. Fase 5
7. Fase 6

---

# Prompt corto para continuar en un nuevo chat
> Continúa la refactorización hexagonal de `core_orchestrator` usando el plan de `docs/PLAN_REFACTORIZACION_HEXAGONAL_CORE_ORCHESTRATOR.md`. Empieza por la Fase 1 y aplica el menor cambio posible, manteniendo `domain` puro, `application` sin imports de `infrastructure`, e inyección completa desde `infrastructure/api/container.py`.

---

# Definition of Done
- [ ] `domain` no importa infraestructura.
- [ ] `application` no importa infraestructura.
- [ ] `MCPClientManager` queda aislado en `infrastructure`.
- [ ] No hay singleton global en reglas.
- [ ] Los casos de uso reciben dependencias por constructor.
- [ ] Hay tests de arquitectura y unitarios para los servicios tocados.

