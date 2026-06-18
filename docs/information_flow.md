# Flujo de Información

El flujo de información en Sentinel SOA está diseñado para procesar telemetría de manera eficiente y escalable. A continuación, se detalla el ciclo de vida de un evento de log dentro del sistema.

1.  **Ingesta de Telemetría**:
    -   Un sistema externo (como un SIEM, un agente de logs, o una aplicación) envía un evento de log en formato JSON al endpoint `/telemetry/` del **Core Orchestrator**. El payload debe incluir un `source_id` que identifique al servidor de origen.

2.  **Gestión de Ventanas**:
    -   El **Core Orchestrator** recibe el log y lo añade a una "ventana de telemetría". Esta ventana agrupa logs que pertenecen a una misma fuente (`source_id`) y sesión (IP de origen) o que han ocurrido en un corto período de tiempo.
    -   El `WindowManager` es el servicio encargado de gestionar estas ventanas, decidiendo cuándo una ventana está "cerrada" y lista para ser analizada (por ejemplo, después de un período de inactividad).

3.  **Solicitud de Análisis**:
    -   Una vez que una ventana se cierra, el **Core Orchestrator** envía una solicitud de análisis al **Log Analysis Server**.
    -   Esta comunicación se realiza a través de `fastmcp`, un protocolo de RPC (Remote Procedure Call) eficiente. La carga útil de la solicitud contiene todos los logs de la ventana.

4.  **Análisis en el Servidor de Logs**:
    -   El **Log Analysis Server** recibe la ventana de logs.
    -   El `HeuristicsEngine` puede realizar un análisis preliminar para detectar patrones obvios o para enriquecer los datos.
    -   El `PromptBuilder` construye un prompt detallado que incluye:
        -   El contexto del análisis de seguridad.
        -   Los logs de la ventana.
        -   Instrucciones específicas sobre qué buscar (por ejemplo, "detectar intentos de inyección de código").
    -   El servicio selecciona el **LLM Provider** configurado (Gemini u Ollama).

5.  **Interacción con el LLM**:
    -   El prompt se envía al modelo de lenguaje (LLM) seleccionado.
    -   El LLM procesa el prompt y devuelve un análisis en formato estructurado (JSON), identificando posibles amenazas, la severidad y las tácticas (por ejemplo, según el framework MITRE ATT&CK).

6.  **Retorno de Resultados**:
    -   El **Log Analysis Server** recibe la respuesta del LLM, la valida y la devuelve al **Core Orchestrator**, de nuevo a través de `fastmcp`.

7.  **Finalización y Alerta**:
    -   El **Core Orchestrator** recibe el análisis final.
    -   En esta etapa, puede realizar acciones adicionales como:
        -   Almacenar el resultado en una base de datos.
        -   Generar una alerta para un sistema de monitoreo.
        -   Devolver el resultado final al cliente que originó la telemetría.
