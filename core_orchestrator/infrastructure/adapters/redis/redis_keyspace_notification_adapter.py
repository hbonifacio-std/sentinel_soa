import asyncio
import json
import logging
from typing import Optional

from redis.asyncio import Redis

from core_orchestrator.domain.ports.telemetry.telemetry_window_cache_port import \
    TelemetryWindowNotificationExpiratoryPort

logger = logging.getLogger(__name__)


class RedisKeyspaceNotificationAdapter(TelemetryWindowNotificationExpiratoryPort):
    def __init__(self, redis_client: Redis):
        self._redis = redis_client
        self._pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
        self._listener_task: Optional[asyncio.Task] = None

    async def _handle_message(self, message: dict) -> None:
        """
        Handles messages received from Redis Pub/Sub channels, specifically expiration events.

        This method processes expiration event notifications, extracts relevant
        information from the message, reconstructs original data keys, and triggers
        custom logic, such as executing analysis for expired windows.

        Parameters:
            message (dict): The message received from the Redis Pub/Sub channel. The
            message should include a "data" key that contains information about the
            expired item.

        Returns:
            None

        Raises:
            Does not explicitly raise exceptions. Any exceptions encountered during
            execution will propagate based on the implementation of Redis and JSON
            operations.

        Note:
            This method skips processing if the "data" key is missing or its value
            cannot be decoded into a string. If "data" represents an expiration event
            for a pre-defined key structure, further analysis and cleanup of the
            associated data are performed asynchronously.
        """
        data = message.get("data")
        if not data:
            return

        # Decode bytearray/bytes to string safely
        if isinstance(data, (bytes, bytearray)):
            key_name = data.decode("utf-8", errors="ignore")
        else:
            key_name = str(data)

        logger.debug("Redis pubsub expiration event received for key: %s", key_name)

        if key_name.startswith(("ttl:window:", "window:")):
            # Reconstruct original data key and clean ID
            original_key = key_name.replace("ttl:", "", 1)
            window_id = original_key.replace("window:", "", 1)

            logger.info("Window expired: %s. Executing analysis.", window_id)

            raw_items = await self._redis.lrange(original_key, 0, -1)
            if raw_items:
                events_as_dicts: list[dict] = [
                    json.loads(item.decode("utf-8")) for item in raw_items
                ]
                logger.info(events_as_dicts)
                await self._redis.delete(original_key)


    async def _listen_loop(self) -> None:
        """
        Handles the asynchronous listening loop for Redis messages and processes them. This function
        is designed to listen for specific message types ("pmessage" or "message") from a Redis pub/sub
        channel and handle them appropriately. Ensures cleanup and logging in case of errors or task
        cancellation.

        Raises:
            asyncio.CancelledError: Raised when the listening loop task is cancelled. Properly logged
                before being re-raised.
            Exception: Logs unexpected exceptions that occur during the listening loop execution.
        """
        try:
            async for message in self._pubsub.listen():
                if message.get("type") in ("pmessage", "message"):
                    await self._handle_message(message)
        except asyncio.CancelledError:
            logger.info("Redis notification listener loop task cancelled.")
            raise
        except Exception as exc:
            logger.exception("Unexpected error in Redis keyspace listener: %s", exc)

    async def start_listening(self) -> None:
        """
        Starts listening for Redis expiration events.

        This asynchronous function configures Redis to emit keyspace notifications for key
        expiration events and subscribes to the appropriate Redis pub/sub channel. It sets up
        a subscription pattern that monitors all database indices and handles the event
        listening loop as a background task.

        Raises:
            Exception: If Redis notify-keyspace-events configuration fails.

        """
        # 1. Auto-configure Redis to emit expiration events if possible
        try:
            await self._redis.config_set("notify-keyspace-events", "AKE")
            logger.info("Set Redis notify-keyspace-events to 'AKE'")
        except Exception as exc:
            logger.warning("Unable to set Redis notify-keyspace-events config: %s", exc)

        # 2. Pattern uses @* to match any Redis DB index automatically
        pattern = "__keyevent@*__:expired"
        logger.info("Subscribing to keyevent notifications for pattern: %s", pattern)

        await self._pubsub.psubscribe(pattern)
        self._listener_task = asyncio.create_task(
            self._listen_loop(), name="redis-keyspace-listener"
        )

    async def stop_listening(self) -> None:
        """
        Stops the listening process for a Redis Pub/Sub system.

        This asynchronous method ensures that all active listening tasks are properly
        terminated and that the Pub/Sub system is cleanly shut down.

        Raises
        ------
        asyncio.CancelledError
            Raised if the listener task is cancelled during shutdown.

        Exception
            Raised if an error occurs during the Pub/Sub listener shutdown.

        """
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                logger.exception("Listener task cancelled during shutdown.")
                raise

        try:
            await self._pubsub.punsubscribe()
            await self._pubsub.close()
            logger.info("Redis Pub/Sub listener shut down cleanly.")
        except Exception as exc:
            logger.warning("Error during Pub/Sub listener shutdown: %s", exc)