# Plan de Acción: Limpieza y Consolidación de la Arquitectura Hexagonal en `core_orchestrator`

Este documento detalla el plan para completar la refactorización hacia una arquitectura hexagonal en el módulo `core_orchestrator`, eliminando el código obsoleto y asegurando la correcta migración de la lógica existente.

---

### **Análisis Arquitectónico**

1.  **Nueva Arquitectura (Objetivo):**
    *   `domain/`: Modelos de negocio (`models`) y contratos/interfaces (`ports`).
    *   `application/`: Lógica de negocio y casos de uso (`services`).
    *   `infrastructure/`: Adaptadores para tecnologías externas (API `api`, persistencia `persistence`, clientes `clients`).
    *   `agent/`: Capa de orquestación de alto nivel para tareas en segundo plano.

2.  **Estructura Antigua (A Eliminar):**
    *   `core_orchestrator/services/`
    *   `core_orchestrator/repositories/`
    *   `core_orchestrator/models/`
    *   `core_orchestrator/security/` (Este será reubicado, no eliminado en primera instancia).

### **Hallazgos Críticos**

El análisis reveló dos problemas principales que impiden la limpieza final:

1.  **Componentes Clave Anclados a Código Antiguo:** El `RulesEngine` y el `agent/runner.py` (que procesa la telemetría) todavía dependen directamente de servicios en el directorio obsoleto `core_orchestrator/services/`.
2.  **Dependencias Cruzadas:** Algunos servicios nuevos en `application/services` están importando modelos desde el directorio antiguo (`core_orchestrator/models/`) en lugar del nuevo (`core_orchestrator/domain/models/`). Esto crea un acoplamiento indebido.

---

### **Plan de Acción Detallado**

**Fase 1: Consolidar los Modelos y Corregir Importaciones**

1.  **Acción:** Mover todos los archivos de modelos (`.py`) del directorio `core_orchestrator/models/` al directorio `core_orchestrator/domain/models/`.
2.  **Acción:** Realizar una búsqueda y reemplazo global en todo el proyecto:
    *   Buscar: `from core_orchestrator.models`
    *   Reemplazar con: `from core_orchestrator.domain.models`
3.  **Verificación:** Asegurarse de que todas las referencias a los modelos ahora apunten a `core_orchestrator.domain.models`.
4.  **Limpieza:** Una vez confirmado que no hay dependencias, eliminar el directorio `core_orchestrator/models/`.

**Fase 2: Reubicar el Módulo de Seguridad**

1.  **Acción:** Mover el directorio completo `core_orchestrator/security/` (junto con su contenido) a `core_orchestrator/infrastructure/security/`.
2.  **Acción:** Actualizar todas las importaciones que hagan referencia a la ubicación anterior de `security`. Por ejemplo:
    *   Buscar: `from core_orchestrator.security`
    *   Reemplazar con: `from core_orchestrator.infrastructure.security`
3.  **Verificación:** Confirmar que todos los módulos que utilizaban `core_orchestrator/security` ahora funcionan correctamente.

**Fase 3: Migrar la Lógica de Telemetría y Agente**

1.  **Acción:** Analizar la lógica contenida en `core_orchestrator/services/window_manager_service.py` y `core_orchestrator/services/telemetry_service.py`.
2.  **Acción:** Crear uno o más servicios nuevos dentro de `core_orchestrator/application/services/` (ej. `telemetry_processing_service.py`) que implementen la funcionalidad de los servicios antiguos.
3.  **Acción:** Refactorizar `core_orchestrator/agent/runner.py` para que utilice este(estos) nuevo(s) servicio(s) de la capa `application` a través de inyección de dependencias, eliminando cualquier referencia directa a los servicios antiguos en `core_orchestrator/services/`.

**Fase 4: Refactorizar el Motor de Reglas (`RulesEngine`)**

1.  **Acción:** Analizar la lógica de `core_orchestrator/services/rules_engine.py` y el `LegacyRuleRepository` en `core_orchestrator/repositories/rules_repository.py`.
2.  **Acción:** Mover la lógica del `RulesEngine` a un nuevo servicio en `core_orchestrator/application/services/` (ej. `rules_engine_service.py`).
3.  **Acción:** Asegurarse de que este nuevo `rules_engine_service.py` utilice el `rule_service.py` correcto (dentro de `application/services`) y su repositorio asociado a través del puerto de dominio, no el `LegacyRuleRepository`.

**Fase 5: Externalizar la Lógica de Arranque (`Bootstrap`)**

1.  **Acción:** Analizar el contenido de `core_orchestrator/services/bootstrap_service.py`.
2.  **Acción:** Mover la lógica de configuración y carga inicial de datos a un script independiente en el directorio raíz `scripts/` (similar a `scripts/bootstrap_local_data.py`). Este script se ejecutará una vez y no será parte del ciclo de vida de la aplicación.
3.  **Limpieza:** Una vez que su lógica haya sido externalizada, eliminar `core_orchestrator/services/bootstrap_service.py`.

**Fase 6: Limpieza Final de Directorios Obsoletos y Dependencias**

1.  **Acción:** Una vez que todas las lógicas de los servicios y repositorios antiguos han sido migradas o externalizadas, eliminar los directorios:
    *   `core_orchestrator/services/`
    *   `core_orchestrator/repositories/`
2.  **Acción:** Revisar y limpiar `core_orchestrator/infrastructure/api/dependencies.py` para eliminar cualquier proveedor de dependencias que aún haga referencia a servicios o repositorios "legacy" (ej. `get_legacy_rule_service`).
3.  **Acción:** Revisar y limpiar `core_orchestrator/main.py` para eliminar cualquier inicialización o uso de servicios o componentes antiguos, asegurando que solo se configuren y utilicen los elementos de la nueva arquitectura.

**Fase 7: Verificación Rigurosa**

1.  **Acción:** Ejecutar todas las pruebas unitarias y de integración del proyecto. Asegurarse de que pasen sin errores.
2.  **Acción:** Iniciar la aplicación (`core_orchestrator`).
3.  **Acción:** Realizar pruebas manuales de los endpoints críticos de la API para confirmar que toda la funcionalidad sigue operativa y no hay regresiones.

---

Este plan debe ejecutarse fase por fase, verificando el correcto funcionamiento al final de cada una para asegurar una migración sin problemas.
