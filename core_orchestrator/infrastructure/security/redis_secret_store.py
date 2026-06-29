import logging
from datetime import datetime, timezone
from typing import Optional

from core_orchestrator.infrastructure.config.database import DatabaseManager

logger = logging.getLogger("core_orchestrator.security.redis_store")


class RedisSecretStore:
    """
    Manejador asíncrono para almacenar secretos de firmas HMAC
    y gestionar la lista negra (blacklist) de JWTs usando un Redis real.
    """

    def __init__(self):
        # Prefijos globales para organizar las llaves dentro de Redis
        self.SECRET_PREFIX = "secret:"
        self.BLACKLIST_PREFIX = "blacklist:"
        self.db = DatabaseManager()
        self.db.connect()
        self.redis = self.db.redis_client

        # Validamos la dependencia crítica en el arranque
        if self.redis is None:
            logger.critical("Error crítico: 'redis' no está conectado.")
            raise RuntimeError(
                "No se pudo inicializar RedisSecretStore porque la conexión a Redis es None. "
            )

    # ============================================================================
    # HMAC Secrets Operations (Async)
    # ============================================================================

    async def get_secret(self, public_key: str) -> Optional[str]:
        """
        Recupera un secreto por su llave pública desde Redis.
        Incluye un fallback para el entorno local de desarrollo.
        """
        key = f"{self.SECRET_PREFIX}{public_key}"
        secret = await self.redis.get(key)

        if secret:
            return secret

        # Fallback controlado exclusivo para desarrollo local simulado
        if public_key == "victim-app-01":
            logger.warning(f"Clave '{public_key}' no encontrada en Redis. Usando secreto por defecto de desarrollo.")
            return "sentinel_sk_live_v1_KLPLxqIZWPaelBI66EUVQKv6xHAMFqP9n"

        return None

    async def set_secret(self, public_key: str, secret: str) -> None:
        """Guarda o actualiza un secreto en Redis sin expiración (permanente)."""
        key = f"{self.SECRET_PREFIX}{public_key}"
        await self.redis.set(key, secret)
        logger.info(f"Secret persistido en Redis para public_key: {public_key}")

    async def delete_secret(self, public_key: str) -> bool:
        """Elimina un secreto de Redis. Retorna True si existía y fue eliminado."""
        key = f"{self.SECRET_PREFIX}{public_key}"
        deleted = await self.redis.delete(key)
        return deleted > 0

    # ============================================================================
    # JWT Blacklist Operations (Con TTL automático de Redis)
    # ============================================================================

    async def blacklist_token(self, token_jti: str, expires_at: datetime) -> None:
        """
        Añade un token a la lista negra en Redis.
        Calcula el TTL restante y delega el borrado automático a Redis.
        """
        now = datetime.now(timezone.utc)

        # Asegurar que el datetime tenga información de zona horaria (UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        # Calculamos los segundos de vida que le quedan al JWT
        ttl_seconds = int((expires_at - now).total_seconds())

        if ttl_seconds <= 0:
            logger.debug(f"El token {token_jti} ya expiró temporalmente, omitiendo almacenamiento.")
            return

        key = f"{self.BLACKLIST_PREFIX}{token_jti}"

        # Guardamos en Redis aplicando el TTL (ex=seconds). Al expirar el tiempo, Redis lo destruye solo.
        await self.redis.set(key, "revoked", ex=ttl_seconds)
        logger.info(f"Token enviado a la blacklist en Redis: {token_jti} (TTL: {ttl_seconds}s)")

    async def is_token_blacklisted(self, token_jti: str) -> bool:
        """Comprueba si el identificador del token (jti) existe en la lista negra."""
        if not token_jti:
            return False

        key = f"{self.BLACKLIST_PREFIX}{token_jti}"
        exists = await self.redis.exists(key)
        return exists > 0

redis_secrets = RedisSecretStore()

