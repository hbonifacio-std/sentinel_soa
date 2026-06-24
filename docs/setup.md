# Guía de Implementación y Configuración

Esta guía proporciona los pasos necesarios para configurar y ejecutar el proyecto Sentinel SOA en un entorno de desarrollo.

## Requisitos Previos

-   Docker y Docker Compose
-   Python 3.9 o superior (para desarrollo local fuera de Docker)
-   Una clave de API de Google Gemini (si se desea usar este proveedor)

## Configuración del Entorno

El proyecto utiliza un archivo `.env` para gestionar las variables de entorno. Puede empezar copiando el archivo de ejemplo:

```bash
cp .env.example .env
```

A continuación, edite el archivo `.env` y configure las siguientes variables:

### Variables de Entorno

| Variable | Descripción | Valor por Defecto/Ejemplo | Obligatorio |
| :--- | :--- | :--- | :--- |
| `LLM_PROVIDER` | Define qué proveedor de LLM se utilizará. Opciones: `gemini` u `ollama`. | `gemini` | Sí |
| `GEMINI_API_KEY` | Tu clave de API para Google Gemini. | `""` | Si `LLM_PROVIDER=gemini` |
| `GEMINI_MODEL` | El modelo específico de Gemini que se va a utilizar. | `gemini-1.5-flash` | Si `LLM_PROVIDER=gemini` |
| `OLLAMA_BASE_URL` | La URL base del servicio Ollama. | `http://ollama:11434` | Si `LLM_PROVIDER=ollama` |
| `OLLAMA_MODEL` | El nombre del modelo local que se utilizará en Ollama. | `sentinel-analyst` | Si `LLM_PROVIDER=ollama` |
| `MONGO_DB_NAME` | Base MongoDB de la aplicación (telemetría, reportes, analytics). | `sentinel_soa` | Sí |
| `RULES_MONGO_DB_NAME` | Base MongoDB dedicada al CRUD y versionado de reglas heurísticas. | `heuristy` | Recomendado |
| `REDIS_RULES_DB` | DB lógica de Redis usada para cachear el bundle activo de reglas. | `3` | Recomendado |
| `RULES_CACHE_TTL_SECONDS` | TTL del bundle de reglas en Redis. | `86400` | No |

**Nota**: Los valores de `OLLAMA_BASE_URL` y `OLLAMA_MODEL` están preconfigurados en `docker-compose.yml` para funcionar dentro del entorno Docker. No es necesario cambiarlos a menos que tengas una configuración personalizada.

### Variables específicas del sistema de reglas

- `MONGO_DB_NAME` y `RULES_MONGO_DB_NAME` **no cumplen el mismo rol**.
- `MONGO_DB_NAME` aloja datos operativos de la aplicación.
- `RULES_MONGO_DB_NAME` aloja:
  - `heuristic_rules`
  - `rule_versions`
  - `rule_audit_log`
- `REDIS_RULES_DB` se usa para cachear el `RulesBundle` activo que luego el core inyecta al MCP server.

Para la documentación funcional completa del subsistema de reglas, consulta:

- **[📄 Guía completa de reglas heurísticas](./rules/README.md)**

## Ejecución del Proyecto

Una vez configurado el archivo `.env`, puedes levantar todos los servicios utilizando Docker Compose:

```bash
docker-compose up --build
```

-   El flag `--build` fuerza la reconstrucción de las imágenes de Docker, lo cual es útil si has realizado cambios en el código o en los `Dockerfile`.
-   La primera vez que se ejecute, Docker descargará las imágenes base y Ollama descargará el modelo `llama3.2:1b`, lo que puede tardar varios minutos.

## Verificación

Para verificar que los servicios están funcionando correctamente:

1.  **Core Orchestrator API**: Abre tu navegador o un cliente de API y accede a `http://localhost:8000/docs`. Deberías ver la documentación interactiva de la API de FastAPI.

2.  **Logs de los Contenedores**: Puedes ver los logs de cada servicio con el siguiente comando:
    ```bash
    # Ver logs de todos los servicios
    docker-compose logs -f

    # Ver logs de un servicio específico (ej. core)
    docker-compose logs -f core
    ```

## Desarrollo Local (Sin Docker)

Si prefieres ejecutar los servicios localmente sin Docker, necesitarás:

1.  **Instalar dependencias**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Ejecutar cada servicio** en una terminal separada, asegurándote de configurar las variables de entorno adecuadas para cada uno.

    -   **Log Analysis Server**:
        ```bash
        # En la terminal 1
        export MCP_SERVER_HOST=localhost
        export MCP_SERVER_PORT=8080
        # ... (resto de variables de LLM)
        python mcp_servers/log_analysis_server/server.py
        ```

    -   **Core Orchestrator**:
        ```bash
        # En la terminal 2
        export MCP_SERVER_HOST=localhost
        export MCP_SERVER_PORT=8080
        # ... (resto de variables de LLM)
        uvicorn core_orchestrator.main:app --host 0.0.0.0 --port 8000 --reload
        ```
    **Nota**: Para el desarrollo local, también necesitarías tener una instancia de Ollama ejecutándose por separado si deseas usarla.
