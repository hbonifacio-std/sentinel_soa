"""
Punto de Entrada y Configuración Maestra del Core Orchestrator.

Inicializa la aplicación FastAPI, orquesta los ciclos de vida de los subprocesos MCP
y monta las rutas HTTP expuestas a la red corporativa.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

from core_orchestrator.config import orchestrator_settings as settings
from core_orchestrator.api.v1.endpoints import telemetry
from core_orchestrator.agent.runner import agent_runner
from core_orchestrator.services.database import db

# Configuración del logging centralizado de producción
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("core_orchestrator.main")


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    """
    Manejador de ciclo de vida asíncrono (FastAPI Lifespan).
    Garantiza que el cliente MCP encienda sus subprocesos concurrentes ANTES
    de abrir las compuertas de la API HTTP, y los apague cleanly al detener el servicio.
    """
    logger.info("=== INICIANDO CONFIGURACIÓN DE ARRANQUE DEL SISTEMA ===")

    # Conectar a las bases de datos
    await db.connect_to_mongo()
    await db.connect_to_redis()

    # Encendemos de forma perezosa el subsistema del agente y los túneles stdio MCP
    await agent_runner.initialize_subsytem()

    logger.info("=== CORE ORCHESTRATOR DESPLEGADO Y OPERATIVO EN PUERTO ===")
    yield

    logger.info("=== INICIANDO PROCESO DE APAGADO DE RECURSOS ===")
    # Apagamos los subprocesos de los servidores MCP hijos para no dejar procesos zombis en el SO
    await agent_runner.shutdown_subsytem()

    # Desconectar de las bases de datos
    await db.close_mongo_connection()
    await db.close_redis_connection()

    logger.info("=== SISTEMA APAGADO CORRECTAMENTE ===")


# Instanciación formal de la app FastAPI implementando el gestor de ciclo de vida
app = FastAPI(
    title="Framework de Orquestación de Agentes de IA - Core",
    version="1.0.0",
    description="Plataforma orientada a servicios para prever intrusiones mediante análisis de telemetría web.",
    lifespan=app_lifespan
)

# Configuración estricta del Middleware de seguridad CORS
app.add_middleware(
    CORSMiddleware,
    # Parametrizar en producción mediante settings.ALLOWED_HOSTS
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inyección e inclusión de routers de endpoints de la versión 1
app.include_router(
    telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"]
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_check():
    """
    Endpoint básico de monitoreo para comprobar la disponibilidad operativa de la API.
    """
    return {
        "status": "healthy",
        "component": "core_orchestrator",
        "mcp_status": "connected" if agent_runner.agent is not None else "disconnected"
    }

if __name__ == "__main__":
    import uvicorn
    # Lanzamiento local explícito para depuración en desarrollo
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
