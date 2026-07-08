# Plan de Incremento de Cobertura de Pruebas Unitarias al 95% para `core_orchestrator`

Este documento detalla la estrategia y el plan de acción para incrementar la cobertura de pruebas unitarias en `core_orchestrator` desde el **56%** actual al objetivo del **95%**.

## Estado Actual de Cobertura
Al ejecutar las pruebas actuales, se tiene un **56%** de cobertura general (1039 sentencias sin probar de un total de 2338). Los componentes con menor cobertura son:

1. **Infraestructura de Agentes y MCP (0% - 16%):**
   - `core_orchestrator/infrastructure/agent/runner.py`
   - `core_orchestrator/infrastructure/agent/mcp_client.py`
   - `core_orchestrator/infrastructure/agent/orchestrator.py`
   - Adaptadores MCP (`mcp_forensic_intelligence_adapter.py`, `mcp_llm_analysis_adapter.py`, etc.)
2. **Endpoints de la API FastAPI (23% - 40%):**
   - `core_orchestrator/infrastructure/api/v1/endpoints/analytics.py`
   - `core_orchestrator/infrastructure/api/v1/endpoints/auth.py`
   - `core_orchestrator/infrastructure/api/v1/endpoints/clients.py`
   - `core_orchestrator/infrastructure/api/v1/endpoints/forensic.py`
   - `core_orchestrator/infrastructure/api/v1/endpoints/rules.py`
   - `core_orchestrator/infrastructure/api/v1/endpoints/telemetry.py`
3. **Persistencia (35% - 43%):**
   - Repositorios MongoDB (`mongo_rules_repository.py`, `mongo_user_repository.py`, etc.)
4. **Seguridad y Utilidades (0% - 47%):**
   - `core_orchestrator/infrastructure/security/dependencies.py`
   - `core_orchestrator/infrastructure/security/jwt_utils.py`
   - `core_orchestrator/infrastructure/security/redis_secret_store.py`

---

## Plan Propuesto

### Fase 1: Configuración y Mocks Base
1. **Instalación de Dependencias de Pruebas:**
   - Asegurar que `pytest-cov` y `pytest-mock` estén correctamente integrados en el entorno de desarrollo.
2. **Configuración de Pytest (`pytest.ini` o `.coveragerc`):**
   - Configurar exclusiones para código no testeable directamente (ej. bloques `if __name__ == "__main__":` o código específico de inicio del servidor que no se puede testear de forma unitaria).
3. **Fixtures Compartidos:**
   - Crear fixtures para mockear la base de datos (MongoDB) y el cliente de caché (Redis).
   - Crear fixtures con `fastapi.testclient.TestClient` configurados para omitir o mockear dependencias de autenticación y rate limiting si es necesario.

### Fase 2: Implementación de Pruebas para Endpoints (API v1)
Crear pruebas de integración y unitarias para los controladores HTTP utilizando `TestClient`:
- [NEW] [test_analytics_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_analytics_endpoints.py)
- [NEW] [test_auth_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_auth_endpoints.py)
- [NEW] [test_clients_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_clients_endpoints.py)
- [NEW] [test_forensic_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_forensic_endpoints.py)
- [NEW] [test_rules_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_rules_endpoints.py)
- [NEW] [test_telemetry_endpoints.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/api/v1/test_telemetry_endpoints.py)

### Fase 3: Pruebas de Seguridad y Dependencias
Probar la lógica de validación de tokens y el hashing de contraseñas:
- [NEW] [test_security_utils.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/security/test_security_utils.py)
- [NEW] [test_security_dependencies.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/security/test_security_dependencies.py)

### Fase 4: Pruebas de Persistencia (Mongo & Redis)
Mockear `pymongo` y `redis` para verificar el comportamiento de los adaptadores de persistencia:
- [NEW] [test_mongo_repositories.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/persistence/test_mongo_repositories.py)
- [NEW] [test_redis_cache.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/cache/test_redis_cache.py)

### Fase 5: Pruebas de Agentes y MCP
Mockear la comunicación de subprocess y las respuestas de los MCP servers para probar:
- [NEW] [test_mcp_adapters.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/agent/test_mcp_adapters.py)
- [NEW] [test_agent_runner.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/core_orchestrator/test/infrastructure/agent/test_agent_runner.py)

---

## Plan de Verificación

### Pruebas Automatizadas
- Comando para ejecutar las pruebas con reporte de cobertura detallado:
  ```bash
  .venv\Scripts\pytest --cov=core_orchestrator --cov-report=term-missing core_orchestrator/test/
  ```

### Criterio de Aceptación
- La cobertura general de `core_orchestrator` debe ser $\ge 95\%$.
- Todas las pruebas deben pasar sin errores ni fallos.
