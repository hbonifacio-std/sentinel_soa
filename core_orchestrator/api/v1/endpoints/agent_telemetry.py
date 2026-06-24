"""
REST Endpoint Module for Telemetry Ingestion.

Maps the FastAPI HTTP routes responsible for receiving bursts of log lines,
processing them, and injecting them into the temporal analysis pipeline.
"""
from datetime import datetime, timezone
import logging
import asyncio
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status

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
    Asynchronous function to save a log document to MongoDB.
    """
    try:
        log_data["created_at_utc"] = datetime.now(timezone.utc)
        await db.get_app_db().raw_telemetry.insert_one(log_data)
    except Exception as e:
        logger.error(f"Error saving log to MongoDB: {e}", exc_info=True)


async def _check_and_process_window_if_full(event: LogEvent):
    """
    Checks if the window has reached the size threshold and, if so,
    processes it immediately in the background.
    """
    window_key = window_manager.get_window_key(event)
    current_size = await window_manager.get_window_size(window_key)

    if current_size >= orchestrator_settings.window_threshold_requests:
        logger.info(
            f"Window '{window_key}' has reached the threshold of {orchestrator_settings.window_threshold_requests} events. "
            "Processing immediately."
        )
        # Try to lock and process to avoid race conditions
        lock = await agent_runner.get_redis_lock(f"lock:{window_key}")
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
    Receives a single telemetry event and routes it to the windows in Redis.
    """
    logger.info(
        f"Single event ingestion request received: {event.model_dump_json()}")

    # Execute the DB insertion as a non-blocking background task
    asyncio.create_task(save_log_to_db(event.model_dump()))

    # Add to the Redis window
    await window_manager.add_log_event(event)

    # Check if the window is full and needs to be processed
    await _check_and_process_window_if_full(event)

    return {
        "status": "accepted",
        "event_buffered": event.model_dump()
    }


@router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_events(events: List[LogEvent]):
    """
    Receives a batch of telemetry events and routes them to the windows in Redis.
    """
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The request body does not contain events."
        )

    # Validate that all events in the batch have the same source_id
    first_source_id = events[0].source_id
    if any(event.source_id != first_source_id for event in events):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All events in a batch must have the same source_id."
        )

    logger.info(
        f"Batch ingestion request received with {len(events)} events from '{first_source_id}'.")

    for event in events:
        # Execute the DB insertion as a non-blocking background task
        asyncio.create_task(save_log_to_db(event.model_dump()))
        # Add to the Redis window
        await window_manager.add_log_event(event)

    logger.debug(f"Processed and queued {len(events)} events.")
    # After a batch, we check the last modified window
    await _check_and_process_window_if_full(events[-1])

    return {
        "status": "accepted",
        "processed_records": len(events)
    }


@router.post("/ingest/raw", status_code=status.HTTP_202_ACCEPTED)
async def ingest_raw_logs(lines: List[str]):
    """
    Receives a massive array of raw log lines (Common/Combined Log Format).
    Performs asynchronous parsing and routes the events to the windows in Redis.
    """
    if not lines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The request body does not contain records."
        )

    logger.info(
        f"Raw ingestion request received with {len(lines)} records.")

    parsed_count = 0
    for line in lines:
        log_model = LogPreprocessor.parse_raw_line(line)
        if log_model:
            # Execute the DB insertion as a non-blocking background task
            asyncio.create_task(save_log_to_db(log_model.model_dump()))
            # Add to the Redis window
            await window_manager.add_log_event(log_model)
            parsed_count += 1

            # Check if the window is full after each parsed event
            await _check_and_process_window_if_full(log_model)

    logger.debug(
        f"Parsing completed successfully. Valid events: {parsed_count}/{len(lines)}")

    return {
        "status": "accepted",
        "processed_records": len(lines),
        "valid_events_buffered": parsed_count
    }


@router.post("/flush", status_code=status.HTTP_200_OK)
async def flush_windows():
    """
    Forces the immediate processing of all active telemetry windows in Redis.
    This operation is useful for testing or debugging scenarios where you need
    to analyze accumulated telemetry without waiting for the windows to expire.
    """
    logger.info("Manual flush request for telemetry windows received.")

    processed_windows = 0

    try:
        keys = await window_manager.get_active_windows()
        if not keys:
            logger.info("No active windows found to process.")
            return {"status": "ok", "message": "No active windows to flush.", "processed_windows": 0}

        for key in keys:
            # We try to get a lock for this key to avoid duplicate processing
            lock = await agent_runner.get_redis_lock(f"lock:{key.decode('utf-8')}")
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
                logger.warning(f"Could not acquire lock for key {key.decode('utf-8')}, skipping. "
                               f"It might already be being processed.")

    except Exception as e:
        logger.error(
            f"Error during manual flush of windows: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during the flush operation: {e}"
        )

    logger.info(
        f"Manual flush completed. Processed windows: {processed_windows}/{len(keys)}")

    return {
        "status": "ok",
        "processed_windows": processed_windows,
        "total_active_windows_found": len(keys)
    }
