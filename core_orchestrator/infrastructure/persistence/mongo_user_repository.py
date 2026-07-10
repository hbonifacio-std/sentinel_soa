"""
MongoDB implementation of the user repository.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.ports.auth.user_repository import UserRepository
from core_orchestrator.domain.models.auth.user import UserInDB, UserCreate
from core_orchestrator.infrastructure.security.password import hash_password

logger = logging.getLogger(__name__)


class MongoUserRepository(UserRepository):
    """
    MongoDB implementation for user persistence.
    """

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager
        self.collection = db_manager.get_auth_db()["users"]

    async def get(self, user_id: str) -> Optional[UserInDB]:
        user_doc = await self.collection.find_one({"user_id": user_id})
        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        user_doc = await self.collection.find_one({"username": username})
        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        user_doc = await self.collection.find_one({"email": email})
        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def create(self, user_create: UserCreate) -> UserInDB:
        # This repository implementation will be simple, the service will have the validation logic
        user_id = str(uuid4())
        hashed_password = hash_password(user_create.password)
        now = datetime.now(timezone.utc)

        user_doc = {
            "user_id": user_id,
            "username": user_create.username,
            "email": user_create.email,
            "hashed_password": hashed_password,
            "role": user_create.role or "viewer",
            "is_active": user_create.is_active if user_create.is_active is not None else True,
            "client_id": user_create.client_id,
            "created_at": now,
            "updated_at": now,
        }

        await self.collection.insert_one(user_doc)
        logger.info(f"User created: {user_create.username} (role: {user_create.role})")

        return UserInDB(**user_doc)

    async def list_all(self) -> List[UserInDB]:
        cursor = self.collection.find({})
        users = await cursor.to_list(length=None)
        return [UserInDB(**doc) for doc in users]

    async def ensure_indexes(self) -> None:
        """Ensure unique indexes required by the users collection."""
        await self.collection.create_index("username", unique=True)
        await self.collection.create_index("email", unique=True)
