# Componentes del Sistema

A continuación, se describen en detalle los componentes que conforman Sentinel SOA.

## 1. Core Orchestrator (`core`)

-   **Dockerfile**: `Dockerfile.core`
-   **Contenedor**: `sentinel_core`
-   **Descripción**: Este servicio actúa como el orquestador central. Sus responsabilidades principales son:
    -   **API Externa**: Expone una API (puerto 8000) para recibir eventos de telemetría de fuentes externas.
    -   **Gestión de Ventanas**: Agrupa los logs entrantes en "ventanas" de tiempo o por sesión de usuario para su análisis contextual.
    -   **Orquestación del Análisis**: Cuando una ventana está lista, invoca al `Log Analysis Server` a través de `fastmcp` para iniciar el proceso de análisis.
    -   **Agregación de Resultados**: Recibe los resultados del análisis, los formatea y puede tomar acciones adicionales, como generar alertas.

## 2. Log Analysis Server (`log-analysis-server`)

-   **Dockerfile**: `Dockerfile.mcp`
-   **Contenedor**: `sentinel_mcp_server`
-   **Descripción**: Este es el microservicio especializado en el análisis de logs. Su lógica interna incluye:
    -   **API Interna**: Expone una API con `fastmcp` (puerto 8080) para ser consumida por el `Core Orchestrator`.
    -   **Motor de Heurísticas**: Aplica reglas y heurísticas predefinidas para una primera capa de análisis y para enriquecer los datos que se enviarán al LLM.
    -   **Constructor de Prompts**: Genera prompts dinámicamente, adaptados a los datos de la telemetría recibida, para guiar al LLM en su tarea de análisis.
    -   **Cliente de LLM**: Se comunica con el `LLM Provider` para enviar los prompts y recibir las conclusiones del modelo.

## 3. Ollama (`ollama`)

-   **Dockerfile**: `Dockerfile.ollama`
-   **Contenedor**: `sentinel_ollama`
-   **Descripción**: Este servicio se utiliza para desplegar y servir modelos de lenguaje de forma local.
    -   **Modelo Local**: Por defecto, descarga y configura un modelo `llama3.2:1b` y crea una versión personalizada llamada `sentinel-analyst` a partir de un `Modelfile`.
    -   **Entorno de Desarrollo/Offline**: Permite que el sistema funcione sin conexión a internet o sin necesidad de una API key de un proveedor externo, lo cual es ideal para desarrollo, pruebas o entornos con restricciones de red.
    -   **Flexibilidad**: Permite experimentar con diferentes modelos de código abierto de forma sencilla.

## 4. Red (`sentinel_net`)

-   **Tipo**: `bridge`
-   **Descripción**: Es una red virtual privada de Docker que permite que los contenedores (`core`, `log-analysis-server`, `ollama`) se comuniquen entre sí de forma segura y eficiente, utilizando los nombres de los servicios como si fueran nombres de host.
