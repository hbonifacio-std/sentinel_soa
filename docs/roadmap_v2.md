# Plan de Evolución: Sentinel SOA 2.0

Este documento describe la hoja de ruta para evolucionar el sistema Sentinel SOA, añadiendo capacidades de persistencia de datos y una capa de caché para mejorar el rendimiento y la funcionalidad.

## Visión General de la Nueva Arquitectura

El objetivo es añadir tres nuevos componentes y hacer que los servicios existentes los utilicen:

1.  **MongoDB**: Actuará como el "lago de datos" (Data Lake) del sistema. Almacenará de forma persistente toda la telemetría cruda y los resultados de los análisis generados. Esto es crucial para el análisis histórico.
2.  **Redis**: Cumplirá dos funciones clave:
    *   **Gestor de Ventanas (Reemplazo)**: Reemplazará al `WindowManager` en memoria del `Core Orchestrator`, haciendo que la gestión de ventanas de telemetría sea persistente y escalable.
    *   **Caché**: Almacenará en caché los resultados de análisis recientes para acelerar las respuestas a consultas repetidas.

---

## Paso 1: Integrar MongoDB como Base de Datos Persistente

**Objetivo**: Guardar cada log y cada resultado de análisis para consultas futuras.

1.  **Añadir MongoDB al `docker-compose.yml`**:
    *   Crear un nuevo servicio `mongodb` utilizando la imagen oficial de MongoDB.
    *   Configurar un volumen llamado `mongo_data` para asegurar la persistencia de los datos, mapeándolo a `/data/db` dentro del contenedor.
    *   Asegurarse de que esté en la misma red (`sentinel_net`).

2.  **Modificar el `Core Orchestrator`**:
    *   Añadir una librería de cliente de MongoDB para Python, preferiblemente una asíncrona como `motor` (`pip install motor`).
    *   **En el endpoint `/telemetry/`**: Después de recibir un log, además de enviarlo al gestor de ventanas (que ahora será Redis), guárdalo en una colección en MongoDB llamada `raw_telemetry`. Cada documento debe incluir el log, la IP de origen, y un `timestamp`.
    *   **Al recibir el resultado del análisis**: Cuando el `Core Orchestrator` reciba el análisis final del `Log Analysis Server`, debe guardarlo en una segunda colección en MongoDB llamada `analysis_reports`. Este documento debe estar vinculado al `window_id` (que ahora incluye el `source_id`) o a los logs originales.

## Paso 2: Integrar Redis para Caché y Gestión de Ventanas

**Objetivo**: Hacer que el sistema sea más robusto y rápido.

1.  **Añadir Redis al `docker-compose.yml`**:
    *   Crear un nuevo servicio `redis` utilizando la imagen oficial de Redis.
    *   Configurar un volumen llamado `redis_data` para asegurar la persistencia de los datos, mapeándolo a `/data` dentro del contenedor.
    *   Añadirlo a la red `sentinel_net`.

2.  **Modificar el `Core Orchestrator` para usar Redis**:
    *   Añadir la librería `redis-py` (`pip install redis`).
    *   **Reimplementar el `WindowManager`**:
        *   Cuando llega un log, en lugar de usar un diccionario en memoria, usa Redis. La clave debe identificar unívocamente la fuente: por cada `source_id` e IP, crea una clave (ej: `window:web-server-01:1.2.3.4`) y usa `RPUSH` para añadir el log a una lista de Redis.
        *   Usa el comando `EXPIRE` de Redis en esa clave para manejar el "cierre" de la ventana por inactividad.
        *   Necesitarás un proceso en segundo plano (un `background task` de FastAPI o un worker separado) que revise las claves expiradas para enviar las ventanas completas al `Log Analysis Server`.
    *   **Implementar la capa de Caché**:
        *   Antes de solicitar un nuevo análisis para una ventana, comprueba si un resultado para una ventana muy similar ya existe en la caché de Redis (ej: `cache:analysis:<hash_de_la_ventana>`). Si existe, devuélvelo directamente.
        *   Después de recibir un análisis, guárdalo en la caché de Redis con un tiempo de expiración (ej: 5 minutos).|