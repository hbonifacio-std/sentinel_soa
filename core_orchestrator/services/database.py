import os
# Use the native asynchronous PyMongo client instead of Motor
from pymongo.asynchronous.mongo_client import AsyncMongoClient
from redis.asyncio import Redis
from typing import Optional


class Database:
    def __init__(self):
        self.mongo_client: Optional[AsyncMongoClient] = None
        self.redis_client: Optional[Redis] = None

    async def connect_to_mongo(self):
        mongo_host = os.getenv("MONGO_HOST") or "mongo"
        mongo_port = os.getenv("MONGO_PORT") or "27017"
        mongo_db_name = os.getenv("MONGO_DB_NAME") or "sentinel_soa"
        mongo_user = os.getenv("MONGO_USER") or ""
        mongo_password = os.getenv("MONGO_PASSWORD") or ""
        mongo_auth_db = os.getenv("MONGO_AUTH_DB") or "admin"

        if mongo_user and mongo_password:
            mongodb_uri = (
                f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"
                f"/{mongo_db_name}?authSource={mongo_auth_db}"
            )
        else:
            mongodb_uri = f"mongodb://{mongo_host}:{mongo_port}/{mongo_db_name}"

        # Initialize the native asynchronous pymongo client
        self.mongo_client = AsyncMongoClient(mongodb_uri)

    async def close_mongo_connection(self):
        await self.mongo_client.close()

    async def connect_to_redis(self):
        redis_host = os.getenv("REDIS_HOST") or "redis"
        redis_port = int(os.getenv("REDIS_PORT") or 6379)
        redis_password = os.getenv("REDIS_PASSWORD") or None
        
        self.redis_client = Redis(
            host=redis_host, 
            port=redis_port, 
            password=redis_password, 
            db=0
        )

    async def close_redis_connection(self):
        if self.redis_client:
            await self.redis_client.close()


db = Database()
