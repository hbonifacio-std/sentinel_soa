import asyncio
import logging

from redis.asyncio import Redis

from core_orchestrator.domain.ports.telemetry.telemetry_window_cache_port import \
    TelemetryWindowNotificationExpiratoryPort

logger = logging.getLogger(__name__)

class RedisKeyspaceNotificationAdapter(TelemetryWindowNotificationExpiratoryPort):
    def __init__(self, redis_client: Redis):
        self._listener_task = None
        self._pubsub = redis_client.pubsub()


    async def _handle_message(self,message: dict) -> None:
        """
        Handles incoming message and processes it based on the event type.

        Processes an incoming message containing event data and channel information.
        If the event type is "expired", it extracts the associated window ID from the
        message's channel and executes the relevant use case.

        Parameters:
            message (dict): The incoming message containing the event type and channel
                information encoded in bytes.

        Returns:
            None
        """
        event_type = message["data"].decode("utf-8")
        if event_type == "expired":
            key = message["channel"].decode("utf-8").split(":", 1)[1]
            window_id = key.replace("window:ttl:", "")


            logger.info(f"Window expired: {window_id}. Executing analysis.")

    async def start_listening(self) -> None:
        pattern = "__keyspace@0__:window:ttl:*"
        logger.info(f"Subscribing to keyspace notifications for pattern: {pattern}")
        await self._pubsub.psubscribe(**{pattern: self._handle_message})
        self._listener_task = asyncio.create_task(self._pubsub.run())