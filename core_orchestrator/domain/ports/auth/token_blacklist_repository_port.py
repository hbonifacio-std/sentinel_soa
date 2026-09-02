from abc import ABC, abstractmethod
from datetime import datetime

class TokenBlacklistRepositoryPort(ABC):
    @abstractmethod
    async def add_to_blacklist(self, jti: str, expires_at: datetime): ...

    @abstractmethod
    async def is_blacklisted(self, jti: str) -> bool: ...
