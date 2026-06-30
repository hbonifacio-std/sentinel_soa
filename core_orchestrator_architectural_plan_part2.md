### **Plan de Mejora para la Arquitectura de `core_orchestrator` - Parte 2**

Este plan continúa la refactorización iniciada en la Parte 1, con el objetivo de migrar los módulos restantes (`analytics`, `auth` y `agent_telemetry`) a la Arquitectura Hexagonal.

#### 1. Análisis del Estado Actual (Continuación)

*   **`endpoints/analytics.py`**: Este módulo presenta un alto acoplamiento con la infraestructura. Los endpoints acceden directamente al repositorio (`telemetry_service.repository.analysis_reports_collection`) y contienen una cantidad significativa de lógica de negocio (creación de pipelines de agregación, manipulación de datos) que debería residir en una capa de servicio de aplicación.
*   **`endpoints/auth.py`**: La lógica de autenticación utiliza un método estático (`UserService.authenticate_user`), lo cual dificulta la testabilidad y la inyección de dependencias. Además, la lógica de logout (blacklist del token) está implementada directamente en el endpoint, incluyendo la obtención de configuración.
*   **`endpoints/agent_telemetry.py`**: Este módulo ya utiliza `Depends` para la inyección de dependencias, lo cual es un buen punto de partida. Sin embargo, depende de un archivo (`core_orchestrator/dependencies.py`) que debe ser consolidado con el nuevo sistema de dependencias centralizado en `infrastructure/api/dependencies.py`.

#### 2. Plan de Refactorización (Pasos 2, 3 y 4)

**Paso 2: Refactorizar el Módulo de `Analytics`**

1.  **Definir el Puerto de Analíticas (`domain/ports/analytics_repository.py`):**
    *   Crear una interfaz `AnalyticsRepository(ABC)` que defina los métodos necesarios para obtener datos de analíticas, por ejemplo:
        ```python
        @abstractmethod
        async def get_paginated_reports(self, query: dict, page: int, limit: int) -> dict: ...
        @abstractmethod
        async def get_report_by_id(self, report_id: str) -> Optional[dict]: ...
        @abstractmethod
        async def update_report(self, report_id: str, updates: dict) -> bool: ...
        @abstractmethod
        async def add_action_to_report(self, report_id: str, action: dict) -> bool: ...
        @abstractmethod
        async def get_distinct_source_ids(self) -> List[str]: ...
        @abstractmethod
        async def get_aggregated_stats(self, pipeline: list) -> List[dict]: ...
        ```

2.  **Crear el Adaptador de Persistencia (`infrastructure/persistence/mongo_analytics_repository.py`):**
    *   Implementar la clase `MongoAnalyticsRepository` que herede de `AnalyticsRepository` y contenga la lógica específica de MongoDB para interactuar con la colección `analysis_reports`.

3.  **Crear el Servicio de Aplicación (`application/services/analytics_service.py`):**
    *   Crear la clase `AnalyticsService` que dependa del puerto `AnalyticsRepository`.
    *   Mover toda la lógica de negocio de los endpoints de `analytics.py` a este servicio. Por ejemplo, la construcción de los pipelines de agregación para las estadísticas debe estar aquí.

4.  **Conectar Inyección de Dependencias (`infrastructure/api/dependencies.py`):**
    *   Añadir las funciones `get_analytics_repository` y `get_analytics_service` para proveer las nuevas clases a través de `Depends`.

5.  **Actualizar el Adaptador de API (`api/v1/endpoints/analytics.py`):**
    *   Refactorizar todos los endpoints para que dependan de `AnalyticsService` (`Depends(get_analytics_service)`).
    *   Eliminar toda la lógica de negocio y el acceso directo al repositorio, delegando las llamadas al `analytics_service`.

**Paso 3: Refactorizar el Módulo de `Auth`**

1.  **Revisar `UserService`:**
    *   Asegurarse de que `UserService.authenticate_user` deje de ser un método estático. La lógica debe estar en un método de instancia para que el servicio pueda ser inyectado. El `get_user_service` en `dependencies.py` ya crea una instancia, por lo que el principal cambio es en el endpoint.

2.  **Definir Puerto para Blacklist de Tokens (`domain/ports/token_blacklist_repository.py`):**
    *   Crear una interfaz `TokenBlacklistRepository(ABC)` con métodos para gestionar la lista negra de tokens JWT.
        ```python
        @abstractmethod
        async def add_to_blacklist(self, jti: str, expires_at: datetime): ...
        @abstractmethod
        async def is_blacklisted(self, jti: str) -> bool: ...
        ```

3.  **Crear Adaptador de Caché (`infrastructure/cache/redis_token_blacklist_repository.py`):**
    *   Implementar `RedisTokenBlacklistRepository` que utilice Redis para almacenar los JTI (identificadores de token) hasta que expiren.

4.  **Crear Servicio de Aplicación (`application/services/auth_service.py`):**
    *   Crear un `AuthService` que orqueste el login y el logout.
    *   Dependerá de `UserService` (para autenticar) y de `TokenBlacklistRepository` (para el logout).
    *   El método `login` contendrá la lógica de autenticar y crear el token.
    *   El método `logout` contendrá la lógica de añadir el token a la blacklist.

5.  **Conectar Inyección de Dependencias (`infrastructure/api/dependencies.py`):**
    *   Añadir `get_token_blacklist_repository` y `get_auth_service`.

6.  **Actualizar Adaptador de API (`api/v1/endpoints/auth.py`):**
    *   Refactorizar los endpoints `login_for_access_token` y `logout` para que utilicen `AuthService` inyectado.

**Paso 4: Consolidar y Finalizar `Agent Telemetry`**

1.  **Unificar Dependencias:**
    *   Inspeccionar el archivo `core_orchestrator/dependencies.py`.
    *   Mover cualquier proveedor de dependencias útil y no duplicado a `infrastructure/api/dependencies.py`.
    *   Eliminar `core_orchestrator/dependencies.py` y actualizar las importaciones en `agent_telemetry.py` para que apunten al archivo centralizado.

2.  **Verificar Servicios:**
    *   Revisar los servicios inyectados (`TelemetryService`, `WindowManagerService`) para confirmar que no tienen fugas de lógica de infraestructura y que dependen de puertos, no de implementaciones concretas. Por ejemplo, `TelemetryService` debería depender de un `TelemetryRepository` (puerto) en lugar de usar directamente un cliente de base de datos. Este paso es de validación y pequeños ajustes.

Este plan de acción completa la migración a una arquitectura limpia, mantenible y escalable.
