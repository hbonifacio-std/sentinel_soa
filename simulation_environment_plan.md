# Plan de Implementación: Entorno de Simulación de Ataques

Este documento describe el plan para crear un entorno de simulación controlado, diseñado para generar telemetría (logs) y enviarla al `Core Orchestrator` de Sentinel SOA. El objetivo es probar y validar la capacidad del sistema para detectar patrones de ataque en un escenario realista y aislado.

## 1. Visión General

El entorno de simulación constará de tres componentes principales:

1.  **Aplicación "Víctima" (`victim-app`)**: Un servidor web con una API REST simple que contiene al menos un endpoint vulnerable. Esta aplicación generará logs estructurados de cada petición que reciba.
2.  **Reenviador de Logs (`log-shipper`)**: Un agente ligero (Filebeat) que se ejecuta junto a la aplicación "víctima". Su única función es monitorear los archivos de log, enriquecer los datos y enviarlos periódicamente al `Core Orchestrator`.
3.  **Simulador de Ataques (`attack-simulator`)**: Un script externo (o una herramienta de pentesting) que genera tráfico, tanto benigno como malicioso, dirigido a la aplicación "víctima".

Este diseño desacopla la generación de logs del envío, simulando una arquitectura de producción robusta.

## 2. Plan de Implementación

### Paso 1: Crear la Aplicación "Víctima"

**Objetivo**: Desarrollar una API REST simple con FastAPI que genere logs en formato JSON.

1.  **Crear la estructura de directorios**:
    ```
    sentinel_soa/
    ├── simulation/
    │   ├── victim_app/
    │   │   ├── main.py
    │   │   └── requirements.txt
    │   └── Dockerfile.victim
    └── ...
    ```

2.  **Desarrollar la API (`main.py`)**:
    *   Usar **FastAPI**.
    *   Crear un endpoint `POST /auth/login` que acepte `username` y `password`.
    *   Crear un endpoint `GET /` para simular tráfico normal.
    *   Implementar un **middleware** de FastAPI para interceptar cada petición.
    *   Dentro del middleware, construir un diccionario de log estructurado (JSON) con los siguientes campos: `timestamp`, `source_ip`, `request_method`, `request_path`, `user_agent`, `status_code`, y `raw_request_body`.
    *   Escribir cada log como una nueva línea en un archivo local, por ejemplo: `/var/log/victim_app/activity.log`.

3.  **Crear `Dockerfile.victim`**:
    *   Usar una imagen base de Python.
    *   Copiar `victim_app/` y `requirements.txt`.
    *   Instalar las dependencias (`fastapi`, `uvicorn`).
    *   Exponer el puerto 8001.
    *   Crear el directorio `/var/log/victim_app`.
    *   Ejecutar la aplicación con `uvicorn`.

### Paso 2: Configurar el Reenviador de Logs (Filebeat)

**Objetivo**: Configurar Filebeat para que lea los logs de la aplicación "víctima" y los envíe al `Core Orchestrator`.

1.  **Crear la estructura de directorios**:
    ```
    sentinel_soa/
    ├── simulation/
    │   ├── filebeat_config/
    │   │   └── filebeat.yml
    │   └── ...
    └── ...
    ```

2.  **Configurar `filebeat.yml`**:
    *   **Input**: Configurar un input de tipo `log` para que monitoree el archivo `/var/log/victim_app/activity.log`.
    *   **Parser**: Especificar que el contenido es JSON, para que Filebeat lo parsee automáticamente.
    *   **Processors**: Usar un procesador `add_fields` para añadir el campo `source_id: "victim-web-server-01"` a cada log. Esto es crucial para que el `Core Orchestrator` sepa de dónde vienen los datos.
    *   **Output**: Configurar la salida a `http` apuntando al endpoint del orquestador: `http://sentinel_core:8000/telemetry/`.

### Paso 3: Integrar los Nuevos Servicios en Docker Compose

**Objetivo**: Añadir los servicios `victim-app` y `log-shipper` al archivo `docker-compose.yml`.

1.  **Definir el servicio `victim-app`**:
    *   Usar `build` para construir la imagen a partir de `Dockerfile.victim`.
    *   Asignarle el nombre de contenedor `sentinel_victim_app`.
    *   Mapear el puerto `8001:8001`.
    *   Conectarlo a la red `sentinel_net`.
    *   Montar un volumen compartido llamado `victim_logs` en `/var/log/victim_app`.

2.  **Definir el servicio `log-shipper`**:
    *   Usar la imagen oficial de Filebeat: `docker.elastic.co/beats/filebeat:8.x.x`.
    *   Asignarle el nombre de contenedor `sentinel_log_shipper`.
    *   Montar el archivo de configuración `simulation/filebeat_config/filebeat.yml` en `/usr/share/filebeat/filebeat.yml`.
    *   Montar el mismo volumen `victim_logs` en modo de solo lectura (`ro`) en `/var/log/victim_app`.
    *   Conectarlo a la red `sentinel_net`.
    *   Añadir una dependencia (`depends_on`) de `victim-app`.

3.  **Definir el volumen `victim_logs`** en la sección de volúmenes de Docker Compose.

### Paso 4: Crear el Simulador de Ataques

**Objetivo**: Crear un script para generar tráfico y probar el sistema.

1.  **Crear el script `attack_simulator.py`** (fuera de Docker, en la raíz del proyecto o en una carpeta `tools/`).
2.  Usar la librería `requests` de Python.
3.  Implementar una función para **tráfico benigno**: un bucle que haga peticiones `GET` a `http://localhost:8001/`.
4.  Implementar una función para **tráfico malicioso**: un bucle que envíe peticiones `POST` a `http://localhost:8001/auth/login` con payloads de inyección SQL en el cuerpo JSON.
    *   Ejemplo de payload: `{"username": "admin' OR '1'='1", "password": "password"}`.

## 3. Flujo de Prueba

1.  Iniciar todo el entorno con `docker-compose up --build`.
2.  Verificar que todos los servicios, incluidos `victim-app` y `log-shipper`, están corriendo.
3.  Ejecutar el script `attack_simulator.py` desde la máquina anfitriona.
4.  Observar los logs del contenedor `sentinel_log_shipper` para confirmar que está enviando los logs.
5.  Observar los logs del contenedor `sentinel_core` para confirmar que está recibiendo la telemetría, procesando las ventanas y enviando los análisis al `log-analysis-server`.
6.  Consultar la base de datos MongoDB para ver los informes de análisis generados.

---