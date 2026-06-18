"""
Módulo del Endpoint REST para la Ingesta de Telemetría.

Mapea las rutas HTTP de FastAPI encargadas de recibir ráfagas de líneas de log,
procesarlas e inyectarlas en el pipeline de análisis temporal.
"""
from datetime import datetime, timezone
import logging
import asyncio
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status, BackgroundTasks

from core_orchestrator.agent.runner import agent_runner
from core_orchestrator.models.log_event import LogEvent
from core_orchestrator.services.preprocessor import LogPreprocessor
from core_orchestrator.services.window_manager import window_manager
from core_orchestrator.services.database import db
from core_orchestrator.config import orchestrator_settings

logger = logging.getLogger("core_orchestrator.api.telemetry")

router = APIRouter()


async def save_log_to_db(log_data: Dict[str, Any]):
    """
    Función asíncrona para guardar un documento de log en MongoDB.
    """
    try:
        log_data["created_at_utc"] = datetime.now(timezone.utc)
        await db.mongo_client.sentinel_soa.raw_telemetry.insert_one(log_data)
    except Exception as e:
        logger.error(f"Error al guardar log en MongoDB: {e}", exc_info=True)


async def _check_and_process_window_if_full(event: LogEvent):
    """
    Comprueba si la ventana ha alcanzado el umbral de tamaño y, si es así,
    la procesa inmediatamente en segundo plano.
    """
    window_key = window_manager.get_window_key(event)
    current_size = await window_manager.get_window_size(window_key)

    if current_size >= orchestrator_settings.window_threshold_requests:
        logger.info(
            f"La ventana '{window_key}' ha alcanzado el umbral de {orchestrator_settings.window_threshold_requests} eventos. "
            "Procesando de inmediato."
        )
        # Intentar bloquear y procesar para evitar condiciones de carrera
        lock = await agent_runner.agent.get_redis_lock(f"lock:{window_key}")
        if await lock.acquire(blocking=False):
            try:
                telemetry_window = await window_manager.process_window(window_key)
                if telemetry_window:
                    asyncio.create_task(agent_runner.run_analysis(telemetry_window.model_dump()))
            finally:
                await lock.release()

@router.post("/", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: LogEvent):
    """
    Recibe un único evento de telemetría y lo enruta a las ventanas en Redis.
    """
    logger.info(
        f"Petición de ingesta de evento único recibida: {event.model_dump_json()}")

    # Ejecutar la inserción en DB como una tarea de fondo no bloqueante
    asyncio.create_task(save_log_to_db(event.model_dump()))

    # Añadir a la ventana de Redis
    await window_manager.add_log_event(event)

    # Comprobar si la ventana está llena y necesita ser procesada
    await _check_and_process_window_if_full(event)

    return {
        "status": "accepted",
        "event_buffered": event.model_dump()
    }


@router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_events(events: List[LogEvent]):
    """
    Recibe un lote de eventos de telemetría y los enruta a las ventanas en Redis.
    """
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El cuerpo de la solicitud no contiene eventos."
        )

    logger.info(
        f"Petición de ingesta de lote recibida con {len(events)} eventos.")

    for event in events:
        # Ejecutar la inserción en DB como una tarea de fondo no bloqueante
        asyncio.create_task(save_log_to_db(event.model_dump()))
        # Añadir a la ventana de Redis
        await window_manager.add_log_event(event)

    logger.debug(f"Procesados y encolados {len(events)} eventos.")
    # Después de un lote, comprobamos la última ventana modificada
    await _check_and_process_window_if_full(events[-1])

    return {
        "status": "accepted",
        "processed_records": len(events)
    }


@router.post("/ingest/raw", status_code=status.HTTP_202_ACCEPTED)
async def ingest_raw_logs(lines: List[str]):
    """
    Recibe un arreglo masivo de líneas crudas de logs (Common/Combined Log Format).
    Realiza el parsing asíncrono y enruta los eventos hacia las ventanas en Redis.
    """
    if not lines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El cuerpo de la solicitud no contiene registros."
        )

    logger.info(
        f"Petición de ingesta cruda recibida con {len(lines)} registros.")

    parsed_count = 0
    for line in lines:
        log_model = LogPreprocessor.parse_raw_line(line)
        if log_model:
            # Ejecutar la inserción en DB como una tarea de fondo no bloqueante
            asyncio.create_task(save_log_to_db(log_model.model_dump()))
            # Añadir a la ventana de Redis
            await window_manager.add_log_event(log_model)
            parsed_count += 1

            # Comprobar si la ventana está llena después de cada evento parseado
            await _check_and_process_window_if_full(log_model)

    logger.debug(
        f"Parsing completado con éxito. Eventos válidos: {parsed_count}/{len(lines)}")

    return {
        "status": "accepted",
        "processed_records": len(lines),
        "valid_events_buffered": parsed_count
    }


@router.post("/flush", status_code=status.HTTP_200_OK)
async def flush_windows():
    """
    Fuerza el procesamiento inmediato de todas las ventanas de telemetría activas en Redis.
    Esta operación es útil para escenarios de prueba o depuración donde se necesita
    analizar la telemetría acumulada sin esperar a que las ventanas expiren.
    """
    logger.info("Solicitud de flush manual de ventanas de telemetría recibida.")

    processed_windows = 0

    try:
        keys = await window_manager.get_active_windows()
        if not keys:
            logger.info("No se encontraron ventanas activas para procesar.")
            return {"status": "ok", "message": "No active windows to flush.", "processed_windows": 0}

        for key in keys:
            # Intentamos obtener un bloqueo para esta clave para evitar procesamiento duplicado
            lock = await agent_runner.agent.get_redis_lock(f"lock:{key.decode('utf-8')}")
            if await lock.acquire(blocking=False):
                try:
                    telemetry_window = await window_manager.process_window(key.decode("utf-8"))
                    if telemetry_window:
                        asyncio.create_task(agent_runner.run_analysis(
                            telemetry_window.model_dump()))
                        processed_windows += 1
                finally:
                    await lock.release()
            else:
                logger.warning(f"No se pudo adquirir el bloqueo para la clave {key.decode('utf-8')}, omitiendo. "
                               f"Es posible que ya esté siendo procesada.")

    except Exception as e:
        logger.error(
            f"Error durante el flush manual de ventanas: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during the flush operation: {e}"
        )

    logger.info(
        f"Flush manual completado. Ventanas procesadas: {processed_windows}/{len(keys)}")

    return {
        "status": "ok",
        "processed_windows": processed_windows,
        "total_active_windows_found": len(keys)
    }
