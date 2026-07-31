import logging
from typing import Optional
from pymongo import  AsyncMongoClient
from redis.asyncio import Redis

from core_orchestrator.domain.exceptions.database_exceptions import DatabaseConnectionFailedError, \
    DatabaseNotConnectedError
from core_orchestrator.infrastructure.config.settings import orchestrator_settings

logger = logging.getLogger("core_orchestrator.database.database_manager")

_MSG_DB_NOT_CONNECTED = "MongoDB client is not connected"
class DatabaseManager:
    def __init__(self):
        self._mongo_settings = orchestrator_settings.database_mongodb
        self._redis_settings = orchestrator_settings.database_redis

        self.mongo_client: Optional[AsyncMongoClient] = None

        self.redis_client_window_telemetry: Optional[Redis] = None
        self.redis_client_auth: Optional[Redis] = None
        self.redis_client_rules: Optional[Redis] = None
        logger.info("Database clients initialized successfully.")

    def connect(self):
        """Initializes all application connections."""
        self._connect_mongo()
        self._connect_redis()

    def disconnect(self):
        """Close all connections cleanly."""
        if self.mongo_client:
             self.mongo_client.close()

        if self.redis_client_window_telemetry:
             self.redis_client_window_telemetry.close()

        if self.redis_client_auth:
             self.redis_client_auth.close()

        if self.redis_client_rules:
             self.redis_client_rules.close()

        logger.info("Database connections closed cleanly.")


    def _connect_mongo(self):
        try:
            mongo_host = self._mongo_settings.host
            mongo_port = self._mongo_settings.port
            mongo_user = self._mongo_settings.user
            mongo_password = self._mongo_settings.password.get_secret_value() if self._mongo_settings.password else ""

            if mongo_user and mongo_password:
                mongodb_uri = (
                    f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/"
                    f"{self._mongo_settings.telemetry_db_name}?authSource=admin"
                )
            else:
                mongodb_uri = f"mongodb://{mongo_host}:{mongo_port}/{self._mongo_settings.telemetry_db_name}"

            self.mongo_client = AsyncMongoClient(mongodb_uri)
        except Exception as e:
            raise DatabaseConnectionFailedError(service_name="MongoDB", details=str(e)) from e

    def _connect_redis(self):
        try:
            redis_host = self._redis_settings.host
            redis_port = self._redis_settings.port
            redis_password = self._redis_settings.password.get_secret_value() if self._redis_settings.password else None

            telemetry_db = self._redis_settings.telemetry_db
            auth_db = self._redis_settings.auth_db
            rules_db = self._redis_settings.rules_db

            self.redis_client_window_telemetry = Redis(
                host=redis_host, port=redis_port, password=redis_password, db=telemetry_db
            )
            self.redis_client_auth = Redis(
                host=redis_host, port=redis_port, password=redis_password, db=auth_db
            )
            self.redis_client_rules = Redis(
                host=redis_host, port=redis_port, password=redis_password, db=rules_db
            )
        except Exception as e:
            raise DatabaseConnectionFailedError(service_name="Redis", details=str(e)) from e

    def _ensure_mongo_client(self) -> AsyncMongoClient:
        if not self.mongo_client:
            raise DatabaseNotConnectedError(client_name="MongoDB")
        return self.mongo_client

    def get_rules_db(self):
        client = self._ensure_mongo_client()
        return client[self._mongo_settings.rules_db_name]

    def get_telemetry_db(self):
        client = self._ensure_mongo_client()
        return client[self._mongo_settings.telemetry_db_name]

    def get_auth_db(self):
        client = self._ensure_mongo_client()
        return client[self._mongo_settings.auth_db_name]
