# Plan de Implementación: Sentinel View

Este documento describe el plan para desarrollar **Sentinel View**, una aplicación web de visualización y consulta interactiva para los datos de seguridad generados y almacenados por el ecosistema Sentinel SOA.

## 1. Visión General

Sentinel View cumplirá dos funciones principales:

1.  **Dashboard de Seguridad**: Ofrecerá una vista consolidada y gráfica de las amenazas detectadas, permitiendo a los analistas de seguridad identificar rápidamente patrones, tendencias y fuentes de ataque. Las visualizaciones se podrán filtrar por el origen de la telemetría (`source_id`).


Este nuevo componente se integrará como un servicio autocontenido dentro del `docker-compose.yml` existente.

## 2. Arquitectura y Pila Tecnológica

Para construir una interfaz de usuario moderna y reutilizar la infraestructura existente, proponemos la siguiente pila:

*   **Backend**: **FastAPI (extendiendo el `core_orchestrator` existente)**. No se creará un nuevo servicio. Se añadirán nuevos endpoints al servicio `core` para servir los datos al frontend.
*   **Frontend**: **React**. Una aplicación de página única (SPA) que consumirá la API expuesta por el `core_orchestrator`. Esto permite una interfaz de usuario rica y desacoplada.
*   **Base de Datos**: **MongoDB** (ya integrada en el sistema). La aplicación se conectará directamente a la instancia de MongoDB para leer los `analysis_reports`.
*   **Contenerización**: **Docker**. Se añadirá un nuevo servicio `frontend` al `docker-compose.yml` que utilizará un servidor web ligero (como Nginx) para servir la aplicación React ya compilada (build).

## 3. Plan de Implementación

### Paso 1: Extender el Backend (`core_orchestrator`) y Crear el Frontend

1.  **Estructura de Directorios**:
    ```
    sentinel_soa/
    ├── core_orchestrator/
    │   ├── api/
    │   │   └── analytics.py  # NUEVO: Endpoints para el frontend
    │   └── main.py                # MODIFICADO: para incluir el nuevo router
    ├── frontend/                  # NUEVO: Directorio para la app de React
    │   ├── public/
    │   ├── src/
    │   ├── package.json
    │   └── Dockerfile.frontend
    └── ...
    ```

2.  **Crear `Dockerfile.frontend`**:
    *   Utilizar una compilación multi-etapa (multi-stage build).
    *   **Etapa 1 (Build)**: Usar una imagen de `node` para instalar dependencias (`npm install`) y compilar la aplicación React (`npm run build`).
    *   **Etapa 2 (Serve)**: Usar una imagen ligera de `nginx`. Copiar los archivos estáticos compilados de la etapa anterior a la carpeta de servicio de Nginx. Copiar una configuración de Nginx para manejar el enrutamiento de la SPA.
    *   Exponer el puerto `80`.

3.  **Actualizar `docker-compose.yml`**:
    *   Añadir un nuevo servicio `frontend`:
        ```yaml
        frontend:
          build:
            context: .
            dockerfile: frontend/Dockerfile.frontend
          container_name: sentinel_frontend
          ports:
            - "3000:80" # Exponer la UI en el puerto 3000 del host
          networks:
            - sentinel_net
          depends_on:
            - core # El frontend depende de la API
        ```
    *   **Importante**: El servicio `core` ya tiene acceso a todas las variables de entorno necesarias (`MONGO_*`, `LLM_*`), por lo que no se necesita configuración adicional de entorno para los nuevos endpoints.

### Paso 2: Desarrollo del Dashboard de Visualización

**Objetivo**: Crear endpoints en el `core_orchestrator` y componentes en React para visualizar los datos.

1.  **Desarrollo de Endpoints de API (`core_orchestrator/api/analytics.py`)**:
    *   Crear un nuevo `APIRouter` de FastAPI.
    *   Endpoint `GET /api/analytics/source_ids`: Devuelve una lista de todos los `source_id` únicos en la colección `analysis_reports`.
    *   Endpoint `GET /api/analytics/reports`: Acepta parámetros de consulta como `source_id` y `time_range`. Realiza una consulta a MongoDB (usando `motor`) y devuelve los informes de análisis.
    *   Endpoint `GET /api/analytics/stats`: Acepta los mismos filtros y utiliza pipelines de agregación de MongoDB para devolver estadísticas pre-calculadas (ej: conteo por `threat_level`, conteo por `kill_chain_phase`). Esto es mucho más eficiente que procesar los datos en el frontend.

2.  **Interfaz de Usuario (React)**:
    *   Crear un componente `Sidebar` que consuma el endpoint `/api/analytics/source_ids` para poblar un selector. Incluirá también un selector de rango de fechas.
    *   Cuando los filtros cambian, la aplicación realiza peticiones a los endpoints `/api/analytics/stats` y `/api/analytics/reports`.

3.  **Gráficos y Visualizaciones (Componentes de React)**:
    *   Utilizar una librería de gráficos como **Recharts**, **Chart.js** o **Nivo**.
    *   **Timeline de Amenazas**: Un gráfico de barras (`st.bar_chart`) que muestre el número de amenazas (`threat_detected: true`) por hora o día.
        *   **Eje X**: Tiempo.
        *   **Eje Y**: Cantidad de alertas.
    *   **Distribución de Niveles de Amenaza**: Un gráfico de tarta o dona que muestre el porcentaje de cada `threat_level`.
    *   **Top 10 IP Atacantes**: Una tabla o gráfico de barras que muestre las IPs de origen con más alertas.
    *   **Fases de Kill Chain más Comunes**: Un gráfico de barras mostrando la frecuencia de cada `kill_chain_phase` identificada.
    *   **Tabla de Alertas Recientes**: Un componente de tabla que muestre los detalles de las últimas alertas.



## 4. Flujo de Prueba

1.  Iniciar todo el entorno con `docker-compose up --build`.
2.  Asegurarse de que los contenedores `sentinel_frontend` y `sentinel_core` se inicien correctamente.
3.  Generar datos de prueba ejecutando el `attack_simulator.py` para poblar la base de datos MongoDB con `analysis_reports`.
4.  Acceder a `http://localhost:3000` en un navegador.
5.  **Probar el Dashboard**:
    *   Verificar que el selector de `source_id` se puebla correctamente.
    *   Seleccionar una fuente y confirmar que todos los gráficos se actualizan y muestran datos coherentes con lo que hay en MongoDB.


---