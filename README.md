# Sentinel SOA

**Sentinel SOA** es un sistema de análisis de telemetría basado en una arquitectura orientada a servicios (SOA), diseñado para detectar patrones de ataque y comportamientos anómalos en tiempo real. Utiliza modelos de lenguaje avanzados (LLMs) para realizar un análisis profundo de los logs, proporcionando una capa de inteligencia de seguridad proactiva.

## Tabla de Contenidos

-   [Visión General](#visión-general)
-   [Tecnologías](#tecnologías)
-   [Arquitectura](#arquitectura)
-   [Componentes](#componentes)
-   [Flujo de Información](#flujo-de-información)
-   [Guía de Implementación](#guía-de-implementación)

## Visión General

El objetivo principal de Sentinel SOA es procesar flujos de datos de telemetría (logs de aplicaciones, eventos del sistema, etc.) para identificar actividades sospechosas que podrían pasar desapercibidas para los sistemas de detección basados en firmas tradicionales. Al agrupar los eventos en ventanas de tiempo y analizarlos en su contexto, el sistema puede descubrir ataques complejos de varios pasos.

## Tecnologías

El proyecto está construido sobre un stack de tecnologías modernas de Python y contenedores:

-   **Backend**: FastAPI
-   **Servidor ASGI**: Uvicorn
-   **Comunicación entre servicios**: `fastmcp` (RPC)
-   **Análisis IA**: Google Gemini y/o modelos locales con Ollama
-   **Contenerización**: Docker y Docker Compose
-   **Validación de datos**: Pydantic
-   **Testing**: Pytest

## Arquitectura

La arquitectura del sistema está diseñada para ser modular y escalable, con componentes bien definidos que se comunican a través de la red.

Para una explicación detallada y un diagrama visual, consulta el documento de arquitectura:
-   **[📄 Ver Documento de Arquitectura](./docs/architecture.md)**

## Componentes

El sistema se divide en varios microservicios, cada uno con una responsabilidad clara. Los componentes principales son el `Core Orchestrator`, el `Log Analysis Server` y el servicio `Ollama` para la ejecución de modelos locales.

Para una descripción en profundidad de cada componente, consulta el siguiente documento:
-   **[📄 Ver Documento de Componentes](./docs/components.md)**

## Flujo de Información

El procesamiento de datos sigue un flujo lógico, desde la ingesta de telemetría hasta la generación del análisis final.

Para entender cómo viajan los datos a través del sistema, consulta el documento sobre el flujo de información:
-   **[📄 Ver Documento de Flujo de Información](./docs/information_flow.md)**

## Guía de Implementación

Para poner en marcha el proyecto, necesitarás configurar las variables de entorno y ejecutar los servicios con Docker Compose.

La guía completa de instalación y configuración se encuentra aquí:
-   **[📄 Ver Guía de Implementación y Configuración](./docs/setup.md)**

---
*Este README fue generado para proporcionar una visión completa y detallada del proyecto Sentinel SOA.*

docker exec -it sentinel_attacker python3 /app/traffic_simulator.py
FROM qwen2.5-coder:7b