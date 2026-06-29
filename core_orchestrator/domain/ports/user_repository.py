"""
Defines the repository interface for user persistence.
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from core_orchestrator.domain.models.user import UserInDB, UserCreate


class UserRepository(ABC):
    """
    Port for user persistence operations.
    """

    @abstractmethod
    async def get(self, user_id: str) -> Optional[UserInDB]:
        """
        Retrieves a user by their ID.
        """
        pass

    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        """
        Retrieves a user by their username.
        """
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        """
        Retrieves a user by their email.
        """
        pass

    @abstractmethod
    async def create(self, user_create: UserCreate) -> UserInDB:
        """
        Creates a new user.
        """
        pass

    @abstractmethod
    async def list_all(self) -> List[UserInDB]:
        """
        Lists all users.
        """
        pass
