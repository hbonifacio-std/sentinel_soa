import os
from slowapi import Limiter
from slowapi.util import get_remote_address

redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", "6379")
redis_password = os.getenv("REDIS_PASSWORD", "")

if redis_password:
    redis_uri = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"
else:
    redis_uri = f"redis://{redis_host}:{redis_port}/0"

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_uri
)
