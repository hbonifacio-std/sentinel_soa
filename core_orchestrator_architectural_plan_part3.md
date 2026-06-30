### **Plan de Refactorización Arquitectónica - Parte 3**

#### **Objetivo**
Continuar la migración a una Arquitectura Hexagonal, enfocándose en la reestructuración de los endpoints de la API y la separación completa de la lógica de negocio para `Users` y `TelemetryClients`.

---

#### **Paso 1: Reestructurar y Segregar los Endpoints de la API**

Actualmente, los endpoints residen en `core_orchestrator/api/v1/endpoints/`. Para alinearse mejor con una estructura hexagonal donde la API es un adaptador de infraestructura, se moverán y se separarán por dominio.

1.  **Crear Nueva Estructura de Directorios:**
    *   Crear el directorio `core_orchestrator/infrastructure/api/v1/endpoints/`.

2.  **Mover y Renombrar Endpoints Existentes:**
    *   Mover `core_orchestrator/api/v1/endpoints/analytics.py` a `core_orchestrator/infrastructure/api/v1/endpoints/analytics.py`.
    *   Mover `core_orchestrator/api/v1/endpoints/agent_telemetry.py` a `core_orchestrator/infrastructure/api/v1/endpoints/telemetry.py`.

3.  **Segregar Endpoints de `auth` y `agent_telemetry`:**
    *   **`auth.py`**: Mantener solo los endpoints de autenticación (`/token`, `/logout`, `/me`) en `core_orchestrator/infrastructure/api/v1/endpoints/auth.py`.
    *   **`users.py`**: Crear un nuevo archivo `core_orchestrator/infrastructure/api/v1/endpoints/users.py` para gestionar el CRUD de usuarios (listar, crear, eliminar), moviendo esta lógica si existe en otro lugar.
    *   **`clients.py`**: Crear un nuevo archivo `core_orchestrator/infrastructure/api/v1/endpoints/clients.py` para gestionar el CRUD de clientes de telemetría, moviendo la lógica desde `telemetry.py`.

4.  **Actualizar `main.py`:**
    *   Modificar las importaciones de los routers para que apunten a la nueva ubicación en `core_orchestrator/infrastructure/api/v1/endpoints/`.
    *   Añadir los nuevos routers para `users` y `clients`.

---

#### **Paso 2: Refactorizar la Gestión de Usuarios (`Users`)**

Separar completamente la lógica de negocio de la persistencia para la gestión de usuarios.

1.  **Definir el Puerto (`domain/ports/user_repository.py`):**
    *   Crear la interfaz `UserRepository(ABC)` que defina métodos para el CRUD de usuarios (`find_by_username`, `save`, `delete`, `list_all`, etc.).

2.  **Crear el Adaptador de Persistencia (`infrastructure/persistence/mongo_user_repository.py`):**
    *   Implementar `MongoUserRepository` que herede de `UserRepository` y contenga la lógica de MongoDB, extrayéndola del actual `UserService`.

3.  **Refactorizar el Servicio de Aplicación (`application/services/user_service.py`):**
    *   Mover `core_orchestrator/services/user_service.py` a `core_orchestrator/application/services/user_service.py`.
    *   Refactorizar la clase `UserService` para que dependa de la interfaz `UserRepository`. Eliminar toda referencia directa a `db_manager` o colecciones de MongoDB.

4.  **Actualizar Inyección de Dependencias (`infrastructure/api/dependencies.py`):**
    *   Crear `get_user_repository` para proveer la implementación de MongoDB.
    *   Actualizar `get_user_service` para que inyecte el `UserRepository`.

---

#### **Paso 3: Refactorizar la Gestión de Clientes de Telemetría (`TelemetryClients`)**

Aplicar el mismo patrón hexagonal para la gestión de clientes de telemetría.

1.  **Definir el Puerto (`domain/ports/telemetry_client_repository.py`):**
    *   Crear la interfaz `TelemetryClientRepository(ABC)` con métodos para el CRUD de clientes (`find_by_id`, `find_by_public_key`, `save`, etc.).

2.  **Crear el Adaptador de Persistencia (`infrastructure/persistence/mongo_telemetry_client_repository.py`):**
    *   Implementar `MongoTelemetryClientRepository` que herede del puerto y contenga la lógica de MongoDB, extrayéndola del actual `TelemetryClientService`.

3.  **Refactorizar el Servicio de Aplicación (`application/services/telemetry_client_service.py`):**
    *   Mover `core_orchestrator/services/telemetry_client_service.py` a `core_orchestrator/application/services/telemetry_client_service.py`.
    *   Refactorizar la clase `TelemetryClientService` para que dependa de `TelemetryClientRepository` y `CacheService` (si es necesario para la caché de clientes).

4.  **Actualizar Inyección de Dependencias (`infrastructure/api/dependencies.py`):**
    *   Crear `get_telemetry_client_repository`.
    *   Actualizar `get_telemetry_client_service` para que inyecte el repositorio.

---

#### **Paso 4: Limpieza Final**

1.  **Eliminar Directorios y Archivos Obsoletos:**
    *   Una vez que toda la lógica haya sido migrada, eliminar el directorio `core_orchestrator/api/`.
    *   Eliminar los archivos originales de los servicios en `core_orchestrator/services/` (`user_service.py`, `telemetry_client_service.py`).
    *   Eliminar el directorio `core_orchestrator/repositories` si ya no se utiliza.

Este plan modulariza y desacopla los componentes restantes, consolidando la arquitectura y facilitando el mantenimiento y las pruebas.
