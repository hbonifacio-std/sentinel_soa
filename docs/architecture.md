# Arquitectura del Proyecto

El sistema Sentinel SOA (Service-Oriented Architecture) está diseñado como un conjunto de microservicios que colaboran para analizar telemetría y detectar posibles amenazas de seguridad. La arquitectura se basa en contenedores Docker, lo que facilita la orquestación y el despliegue de los componentes.

## Diagrama de Arquitectura (Producción)

El siguiente diagrama ilustra una arquitectura de producción segura, donde solo el Proxy Inverso es accesible desde el exterior.

```
graph TD
    subgraph "Cliente Externo"
        A[Usuario/SIEM]
    end

    subgraph "Plataforma Sentinel SOA"
        B(Core Orchestrator)
        C(Log Analysis Server)
        G[Tools MCP]
        D(LLM Provider Abstraction)
    end

    subgraph "Modelos de Lenguaje"
        E[Google Gemini]
        F[Ollama (Local)]
    end

    A --"Envía telemetría (logs)"--> B
    B --"1. Invoca 'analyze_web_activity'"--> G
    G --"Ejecuta lógica de análisis"--> C
    C --"Consulta al LLM"--> D
    D --"Selecciona proveedor"--> E
    D --"Selecciona proveedor"--> F
    E --"Respuesta del análisis"--> D
    F --"Respuesta del análisis"--> D
    D --"Retorna análisis"--> C
    C --"Retorna resultado"--> G
    G --"Retorna resultado a B"--> B
    B --"2. Si hay amenaza, invoca 'get_threat_context'"--> G
    B --"3. Sintetiza y retorna alerta final"--> A

    style B fill:#f9f,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#9cf,stroke:#333,stroke-width:2px
```

## Descripción de Componentes

-   **Core Orchestrator**: Contiene el **Agente de IA principal** del sistema. Recibe la telemetría, gestiona las ventanas de tiempo y utiliza un LLM para decidir qué **herramientas** invocar con el fin de analizar los datos y detectar amenazas. Es el cerebro que dirige el flujo de análisis.

-   **Log Analysis Server**: Es el cerebro del sistema de análisis. Utiliza un motor de heurísticas y se apoya en un proveedor de LLM para analizar los datos de telemetría y detectar comportamientos anómalos o maliciosos.

-   **Tools MCP (FastMCP)**: Es el **protocolo de comunicación (RPC)** que actúa como puente entre el `Core Orchestrator` y el `Log Analysis Server`. Su responsabilidad es permitir que el agente invoque "herramientas" remotas (como `analyze_web_activity`) de forma segura y eficiente, abstrayendo la complejidad de la red.

-   **LLM Provider Abstraction**: Es una capa de abstracción dentro del `Log Analysis Server` que le permite comunicarse con diferentes modelos de lenguaje (LLMs), ya sea un servicio en la nube como Google Gemini o un modelo local a través de Ollama.

-   **Modelos de Lenguaje (LLMs)**: Son los encargados de procesar el lenguaje natural y realizar el análisis de los logs, siguiendo las instrucciones proporcionadas en los prompts. El sistema es flexible y puede configurarse para usar diferentes modelos.
