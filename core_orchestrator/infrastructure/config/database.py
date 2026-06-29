import os
import logging
from typing import Optional
from pymongo import  AsyncMongoClient
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self):
        self.mongo_client: Optional[AsyncMongoClient] = None
        self.redis_client: Optional[Redis] = None

        # Cargar variables de entorno una sola vez en el init o usar Pydantic Settings
        self.app_mongo_db_name = os.getenv("MONGO_DB_NAME", "sentinel_soa")
        self.auth_mongo_db_name = os.getenv("AUTH_MONGO_DB_NAME", "auth")
        self.rules_mongo_db_name = os.getenv("RULES_MONGO_DB_NAME", "heuristic")

    def connect(self):
        """Inicializa todas las conexiones de la app"""
        self._connect_mongo()
        self._connect_redis()

    def disconnect(self):
        """Cierra todas las conexiones limpiamente"""
        if self.mongo_client:
             self.mongo_client.close()
        if self.redis_client:
             self.redis_client.close()
        if self.redis_client:
             self.redis_client.close()

    def _connect_mongo(self):
        mongo_host = os.getenv("MONGO_HOST", "mongo")
        mongo_port = os.getenv("MONGO_PORT", "27017")
        mongo_user = os.getenv("MONGO_USER", "")
        mongo_password = os.getenv("MONGO_PASSWORD", "")
        mongo_auth_db = os.getenv("MONGO_AUTH_DB", "admin")

        if mongo_user and mongo_password:
            mongodb_uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/{self.app_mongo_db_name}?authSource={mongo_auth_db}"
        else:
            mongodb_uri = f"mongodb://{mongo_host}:{mongo_port}/{self.app_mongo_db_name}"

        self.mongo_client = AsyncMongoClient(mongodb_uri)

    def _connect_redis(self):
        redis_host = os.getenv("REDIS_HOST", "redis")
        redis_port = int(os.getenv("REDIS_PORT", 6379))
        redis_password = os.getenv("REDIS_PASSWORD", None)

        self.redis_client = Redis(host=redis_host, port=redis_port, password=redis_password, db=0)

        rules_db = int(os.getenv("REDIS_RULES_DB", "3"))
        self.redis_client = Redis(host=redis_host, port=redis_port, password=redis_password, db=rules_db)

    def get_rules_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        return self.mongo_client[self.rules_mongo_db_name]

    def get_telemetry_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        # Telemetry is usually stored in the app DB or a specific telemetry DB
        return self.mongo_client[self.app_mongo_db_name]

    def get_sentinel_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        return self.mongo_client[self.app_mongo_db_name]

    def get_auth_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        return self.mongo_client[self.auth_mongo_db_name]
