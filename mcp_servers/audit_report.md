# Auditoría y Plan de Refactorización de Pruebas: MCP Servers

Este documento detalla el diagnóstico actual, la deuda técnica y el plan de implementación de pruebas unitarias para el directorio `mcp_servers/log_analysis_server`, con el objetivo de alcanzar una cobertura superior al **90%** y garantizar la estabilidad, mantenibilidad y seguridad del sistema sin modificar la lógica del negocio.

---

## 1. Diagnóstico Actual

### 1.1. Estado de Cobertura y Pruebas
Actualmente, el proyecto cuenta con un total de **10 pruebas** (todas ubicadas en `test/integration/`), de las cuales **4 fallan** debido a:
1. **Llamadas de Red Activas (Ollama/External LLMs)**: Las pruebas de `test_forensic_nlq_tools.py` intentan conectarse a un servidor de Ollama local (`http://localhost:11434`), lo cual falla si el servicio no está levantado en el entorno de pruebas.
2. **Errores de Mocking en Atributos de Clase**: Las pruebas de `test_llm_minimal_contract.py` intentan hacer `monkeypatch.setattr(LLMAnalyzer, "_provider", ...)` sobre la clase `LLMAnalyzer`, pero este atributo es dinámico y se define a nivel de instancia (`self._provider`), causando un `AttributeError`. Además, invocan el método de instancia `analyze_with_context` como si fuera de clase.

### 1.2. Mapeo de Cobertura Actual (Total: 49%)
| Módulo / Archivo | Cobertura | Problemas Principales |
|---|---|---|
| `config.py` | 81% | Falta probar validadores y carga de valores límite. |
| `llm_providers/` | 27% (Promedio) | Las clases `GeminiProvider`, `GroqProvider`, `OpenAIProvider` tienen 0% de cobertura. No hay mocks de red (`httpx`). |
| `server.py` | 0% | No se prueba la inicialización del servidor FastMCP ni el registro/ejecución de sus endpoints (herramientas). |
| `services/heuristics_engine.py` | 63% | Falta de cobertura en combinaciones complejas de telemetría y reglas personalizadas. |
| `services/translate_mongo.py` | 48% | Acoplamiento a llamadas de red; no se prueban los extractores JSON ni el manejo de fallos del LLM de manera aislada. |
| `tools/analyze_activity.py` | 43% | Falta probar la matriz MITRE, el control de firmas y flujos alternativos cuando el LLM retorna respuestas corruptas. |
| `tools/forensic_nlq.py` | 64% | El muestreo inteligente (`intelligent_sampling`) y la generación de reportes no están completamente cubiertos en casos extremos de volumen. |

---

## 2. Plan de Refactorización y Pruebas

### 2.1. Objetivos del Plan
*   **Cobertura > 90%** en todo el módulo `log_analysis_server`.
*   **Aislamiento Total**: Cero dependencias externas. Todos los proveedores de LLM y llamadas HTTP deben simularse (`mock`).
*   **Cero Modificaciones de Lógica de Negocio**: Solo se refactorizarán los tests y setups de prueba. El código fuente de negocio se mantendrá intacto.

### 2.2. Cambios Propuestos

#### [MODIFY] [test_llm_minimal_contract.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/integration/test_llm_minimal_contract.py)
*   Corregir el mocking de `LLMAnalyzer._provider` instanciando la clase correctamente e inyectando el mock en la instancia.
*   Corregir las firmas de llamada de `analyze_with_context`.

#### [MODIFY] [test_forensic_nlq_tools.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/integration/test_forensic_nlq_tools.py)
*   Mockear las llamadas de traducción de MongoDB (`TranslateMongo.translate_query`) para evitar conexiones a Ollama.

#### [NEW] Unit Tests en `test/unit/`
Crearemos las siguientes suites de pruebas unitarias puras:
*   [NEW] [test_config.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/unit/test_config.py): Validar carga de variables de entorno y mapeo de secretos.
*   [NEW] [test_providers.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/unit/test_providers.py): Testear `GeminiProvider`, `OllamaProvider`, `GroqProvider`, y `OpenAIProvider` usando `pytest-mock` y mockeando `httpx.AsyncClient`.
*   [NEW] [test_heuristics.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/unit/test_heuristics.py): Probar exhaustivamente el motor de heurísticas con diferentes inputs (RPS alto, User-Agents sospechosos, payloads maliciosos).
*   [NEW] [test_translate_mongo.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/unit/test_translate_mongo.py): Validar la extracción regex de JSON y comportamiento de fallback de traducción.
*   [NEW] [test_server.py](file:///c:/Users/hanse/Documents/Documents/proyecto%20sentinela%20soa/sentinel_soa/mcp_servers/log_analysis_server/test/unit/test_server.py): Testear el registro de herramientas en FastMCP y respuestas de error del servidor.

---

## 3. Plan de Verificación

### Pruebas Automatizadas
Para verificar el éxito del plan, ejecutaremos las pruebas y mediremos la cobertura:
```bash
.venv\Scripts\pytest --cov=mcp_servers/log_analysis_server mcp_servers/log_analysis_server/test
```
El criterio de aceptación es que todas las pruebas pasen y la cobertura total supere el **90%**.
