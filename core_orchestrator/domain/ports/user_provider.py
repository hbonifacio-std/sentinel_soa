# core_orchestrator/domain/ports/user_provider.py
from abc import ABC, abstractmethod
from typing import Optional

from core_orchestrator.domain.models.user import UserInDB


class UserProvider(ABC):
    """
    Port for providing user-related data to other services.

    This interface decouples services that need user information
    from the concrete implementation of the UserService.
    """

    @abstractmethod
    async def authenticate_user(self, username: str, password: str) -> Optional[UserInDB]:
        """
        Authenticates a user and returns the user object if successful.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """
        Retrieves a user by their unique ID.
        """
        raise NotImplementedError
