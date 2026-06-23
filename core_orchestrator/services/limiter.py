# Nuevo archivo: core_orchestrator/core/limiter.py
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# Inicializamos el limiter aquí para que sea un módulo neutral
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", "6379")
redis_password = os.getenv("REDIS_PASSWORD", "")

# 2. Construimos la URI incluyendo la contraseña si existe
if redis_password:
    # Formato con contraseña: redis://:password@host:port/0
    redis_uri = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"
else:
    # Formato sin contraseña (por si acaso en local no tiene)
    redis_uri = f"redis://{redis_host}:{redis_port}/0"
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_uri
)