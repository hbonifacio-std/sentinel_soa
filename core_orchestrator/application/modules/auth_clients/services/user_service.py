"""
User management service for business logic and orchestration.

Handles user creation, retrieval, and authentication logic,
coordinating with the persistence layer through the UserRepository port.
"""

import logging
from typing import Optional

from core_orchestrator.domain.ports.auth.user_provider import UserProvider
from core_orchestrator.domain.ports.auth.password_hasher import PasswordHasherPort
from core_orchestrator.domain.ports.auth.user_repository import UserRepository
from core_orchestrator.domain.models.auth.user import UserInDB, UserCreate

logger = logging.getLogger(__name__)


class UserService(UserProvider):
    """Service for managing user business logic."""

    def __init__(self, user_repository: UserRepository, password_hasher: PasswordHasherPort):
        """
        Initializes the service with a user repository.
        """
        self._user_repository = user_repository
        self._password_hasher = password_hasher

    async def create_user(self, user_create: UserCreate) -> UserInDB:
        """
        Creates a new user after validating business rules.
        """
        # Check if username already exists
        if await self._user_repository.get_by_username(user_create.username):
            raise ValueError(f"Username '{user_create.username}' already exists")

        # Check if email already exists
        if await self._user_repository.get_by_email(user_create.email):
            raise ValueError(f"Email '{user_create.email}' already exists")

        # Delegate creation to the repository
        return await self._user_repository.create(user_create)

    async def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """
        Get a user by ID.
        """
        return await self._user_repository.get(user_id)

    async def get_user_by_username(self, username: str) -> Optional[UserInDB]:
        """
        Get a user by username.
        """
        return await self._user_repository.get_by_username(username)

    async def authenticate_user(self, username: str, password: str) -> Optional[UserInDB]:
        """
        Authenticate a user with username and password.
        """
        user = await self.get_user_by_username(username)

        if not user or not user.is_active:
            return None

        if not self._password_hasher.verify_password(password, user.hashed_password):
            logger.warning(f"Failed login attempt for user: {username}")
            return None

        logger.info(f"User authenticated: {username}")
        return user
