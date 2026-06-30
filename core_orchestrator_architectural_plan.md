### **Plan de Mejora para la Arquitectura de `core_orchestrator`**

Este plan te guiará para transformar tu API en una solución escalable y mantenible, aplicando principios de diseño de software modernos.

#### 1. Análisis del Estado Actual

El análisis revela una arquitectura en capas con los siguientes puntos de fricción:

*   **Acoplamiento Fuerte:** Los servicios (`services/`) dependen directamente de implementaciones concretas de los repositorios (`repositories/`) y de clientes de infraestructura como Redis. Esto viola el Principio de Inversión de Dependencias (DIP).
*   **Anti-patrón Service Locator:** El uso de `app.state` en `main.py` para almacenar e inyectar servicios oculta las dependencias reales de los componentes, haciendo el código más difícil de razonar, probar y mantener. El framework FastAPI provee un sistema de Inyección de Dependencias superior que debe ser aprovechado.
*   **Responsabilidades Mezcladas:** La lógica de negocio se encuentra dispersa. Los endpoints de la API (`api/v1/endpoints/`) contienen lógica que debería estar en los servicios, y los servicios contienen lógica de acceso a datos o cacheo que debería ser abstraída.
*   **Modelos Anémicos:** Existe un único conjunto de modelos Pydantic (`models/`) que se utiliza para todo: validación de entrada de la API, lógica de negocio y persistencia en la base de datos. Esto crea una alta rigidez; un cambio en la base de datos puede forzar un cambio en la API, y viceversa.

#### 2. Propuesta de Arquitectura Hexagonal (Puertos y Adaptadores)

Proponemos una estructura que aísla la lógica de negocio de los detalles de infraestructura (frameworks, bases de datos, etc.).

*   **Capa de Dominio (El Hexágono - `core_orchestrator/domain`)**:
    *   **Modelos de Dominio (`domain/models.py`):** Contendrá las clases y tipos de datos que representan los conceptos de negocio (ej: `HeuristicRule`, `User`). Serán objetos ricos, con su propia lógica y validaciones, independientes de cualquier framework.
    *   **Puertos (`domain/ports/`):** Directorio con las **interfaces** (contratos) que definen cómo el dominio se comunica con el exterior. Serán clases abstractas (`abc.ABC`). Por ejemplo, `domain/ports/rule_repository.py` definiría `class RuleRepository(ABC): @abstractmethod def get_by_id(...)`. Los servicios de aplicación dependerán de estos puertos, no de sus implementaciones.

*   **Capa de Aplicación (`core_orchestrator/application`)**:
    *   **Servicios de Aplicación (`application/services.py`):** Orquestan la lógica de negocio y los casos de uso. Recibirán como dependencias los **puertos** del dominio. Por ejemplo, `RulesService` recibirá una instancia de `RuleRepository` (el puerto, no la implementación de Mongo). Su única responsabilidad es ejecutar la lógica del caso de uso.

*   **Capa de Infraestructura (Adaptadores - `core_orchestrator/infrastructure`)**:
    *   **Adaptadores de Entrada (`infrastructure/api/`):** Son los que inician la interacción. Aquí vivirán los routers de FastAPI. Su trabajo es recibir la petición HTTP, validarla (usando DTOs o "Data Transfer Objects"), llamar al servicio de aplicación correspondiente y formatear la respuesta HTTP.
    *   **Adaptadores de Salida (`infrastructure/persistence/`, `infrastructure/clients/`):** Son las implementaciones concretas de los puertos de salida.
        *   `infrastructure/persistence/mongo_rule_repository.py` contendrá la clase `MongoRuleRepository` que implementa el puerto `RuleRepository` y contiene la lógica para hablar con MongoDB.
        *   `infrastructure/cache/redis_cache.py` implementará un puerto `CachePort`.

#### 3. Aplicación de Principios SOLID

Esta nueva estructura refuerza los principios SOLID de forma natural:

*   **SRP (Single Responsibility Principle):** Cada componente tiene una única razón para cambiar. La API se encarga del HTTP, los servicios de la lógica de negocio y los repositorios del acceso a datos.
*   **OCP (Open/Closed Principle):** El núcleo del negocio (`domain` y `application`) está cerrado a modificaciones pero abierto a extensiones. Puedes añadir un repositorio para PostgreSQL implementando el puerto correspondiente sin tocar ni una línea de la lógica de negocio.
*   **LSP (Liskov Substitution Principle):** Se garantiza al hacer que los adaptadores implementen correctamente las interfaces (puertos).
*   **ISP (Interface Segregation Principle):** Creamos puertos pequeños y cohesivos para cada funcionalidad (`UserRepository`, `RulesRepository`) en lugar de una interfaz monolítica.
*   **DIP (Dependency Inversion Principle):** Es la clave de todo. Las capas de alto nivel (negocio) no dependen de las de bajo nivel (infraestructura), sino que ambas dependen de abstracciones (los puertos).

#### 4. Mejoras de Seguridad Sugeridas

La implementación actual en `security/dependencies.py` es un punto fuerte. Se integrará de la siguiente manera:

1.  Las dependencias de seguridad (`get_current_user`) se seguirán utilizando en la capa de **adaptadores de entrada** (los endpoints de FastAPI).
2.  El endpoint recibirá el modelo del usuario autenticado y pasará únicamente los datos necesarios (ej: `user_id`, `user_role`) al **servicio de aplicación**.
3.  El servicio de aplicación debe ser agnóstico a la autenticación. No debe recibir un objeto `User` de la base de datos, sino los datos mínimos para realizar su trabajo y verificar permisos si es necesario. Esto mantiene la lógica de negocio desacoplada del esquema de seguridad.

#### 5. Plan de Refactorización Accionable (Paso a Paso)

Te recomiendo realizar esta refactorización de forma incremental, endpoint por endpoint o funcionalidad por funcionalidad.

**Paso 0: Preparar el Terreno**

1.  Crea la nueva estructura de directorios:
    ```
    core_orchestrator/
    ├── application/
    │   └── services/
    ├── domain/
    │   ├── models/
    │   └── ports/
    └── infrastructure/
        ├── api/
        │   └── v1/
        ├── persistence/
        └── clients/
    ```
2.  Elimina por completo el uso de `app.state` en `main.py` y las dependencias que lo consumen. De ahora en adelante, todo se gestionará con `fastapi.Depends`.

**Paso 1: Refactorizar `Rules` (Ejemplo)**

1.  **Definir Modelos de Dominio (`domain/models/rules.py`):** Mueve la definición de `HeuristicRule` aquí. Límpiala de decoradores o configuraciones específicas de la base de datos si las tuviera.

2.  **Definir el Puerto (`domain/ports/rule_repository.py`):**
    ```python
    from abc import ABC, abstractmethod
    from typing import List, Optional
    from core_orchestrator.domain.models.rules import HeuristicRule

    class RuleRepository(ABC):
        @abstractmethod
        async def get_by_id(self, rule_id: str) -> Optional[HeuristicRule]:
            raise NotImplementedError

        @abstractmethod
        async def get_all(self) -> List[HeuristicRule]:
            raise NotImplementedError
        
        # ... otros métodos ...
    ```

3.  **Crear el Adaptador de Persistencia (`infrastructure/persistence/mongo_rule_repository.py`):**
    *   Mueve la clase `RuleRepository` actual a este nuevo archivo y renómbrala a `MongoRuleRepository`.
    *   Haz que implemente el puerto: `class MongoRuleRepository(RuleRepository): ...`
    *   Asegúrate de que todos los métodos definidos en el puerto estén implementados.

4.  **Refactorizar el Servicio de Aplicación (`application/services/rule_service.py`):**
    ```python
    from core_orchestrator.domain.ports.rule_repository import RuleRepository

    class RuleService:
        def __init__(self, rule_repository: RuleRepository):
            self.rule_repository = rule_repository

        async def fetch_rule_by_id(self, rule_id: str):
            # Lógica de negocio aquí...
            return await self.rule_repository.get_by_id(rule_id)
    ```
    Nota cómo ahora `RuleService` depende de la abstracción `RuleRepository`, no de la implementación de Mongo.

5.  **Conectar Todo con Inyección de Dependencias (`infrastructure/api/dependencies.py`):**
    ```python
    # Este es el corazón de la inyección de dependencias
    
    from core_orchestrator.application.services.rule_service import RuleService
    from core_orchestrator.domain.ports.rule_repository import RuleRepository
    from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
    from core_orchestrator.config.database import DatabaseManager # Asumiendo que esta es tu clase de conexión

    def get_db_manager() -> DatabaseManager:
        # Lógica para obtener tu manager de DB
        return DatabaseManager()

    def get_rule_repository(db: DatabaseManager = Depends(get_db_manager)) -> RuleRepository:
        return MongoRuleRepository(db)

    def get_rule_service(repo: RuleRepository = Depends(get_rule_repository)) -> RuleService:
        return RuleService(repo)
    ```

6.  **Actualizar el Adaptador de API (`infrastructure/api/v1/rules.py`):**
    ```python
    from fastapi import APIRouter, Depends
    from core_orchestrator.application.services.rule_service import RuleService
    from .dependencies import get_rule_service

    router = APIRouter()

    @router.get("/rules/{rule_id}")
    async def get_rule(rule_id: str, rule_service: RuleService = Depends(get_rule_service)):
        rule = await rule_service.fetch_rule_by_id(rule_id)
        if not rule:
            # ... manejo de error ...
        return rule
    ```

Este plan te proporciona un camino claro para desacoplar tu aplicación, hacerla más testeable y prepararla para el futuro crecimiento. Te sugiero empezar con un solo endpoint para familiarizarte con el flujo antes de migrar el resto de la aplicación.
