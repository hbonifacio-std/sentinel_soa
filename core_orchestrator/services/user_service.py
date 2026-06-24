"""
User management service for CRUD operations and authentication.

Handles user creation, retrieval, and authentication operations
with MongoDB as the persistent storage.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4
from core_orchestrator.models.user import UserInDB, UserCreate, UserResponse
from core_orchestrator.security.password import hash_password, verify_password
from core_orchestrator.services.database import db

logger = logging.getLogger("core_orchestrator.services.user_service")


class UserService:
    """Service for managing user CRUD operations and authentication."""

    @staticmethod
    async def ensure_indexes() -> None:
        """Ensure unique indexes required by the users collection."""
        collection = await UserService.get_user_collection()
        await collection.create_index("username", unique=True)
        await collection.create_index("email", unique=True)
    
    @staticmethod
    async def get_user_collection():
        """Get the users collection from MongoDB."""
        return db.get_app_db().users
    
    @staticmethod
    async def create_user(user_create: UserCreate) -> UserInDB:
        """
        Create a new user in MongoDB.
        
        Args:
            user_create: User creation model with password
        
        Returns:
            Created user model
        
        Raises:
            ValueError: If username or email already exists
        """
        collection = await UserService.get_user_collection()
        
        # Check if username already exists
        existing_user = await collection.find_one({"username": user_create.username})
        if existing_user:
            raise ValueError(f"Username '{user_create.username}' already exists")
        
        # Check if email already exists
        existing_email = await collection.find_one({"email": user_create.email})
        if existing_email:
            raise ValueError(f"Email '{user_create.email}' already exists")
        
        # Hash password and create user document
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
            "created_at": now,
            "updated_at": now,
        }
        
        await collection.insert_one(user_doc)
        logger.info(f"User created: {user_create.username} (role: {user_create.role})")
        
        return UserInDB(**user_doc)

    @staticmethod
    async def seed_user(user_create: UserCreate, overwrite_existing: bool = False) -> tuple[UserInDB, bool]:
        """
        Create a seed user if missing, optionally updating existing records.

        Returns:
            tuple[UserInDB, bool]: (user, created)
        """
        collection = await UserService.get_user_collection()
        existing_user = await collection.find_one({"username": user_create.username})

        if not existing_user:
            created = await UserService.create_user(user_create)
            return created, True

        user = UserInDB(**existing_user)
        if not overwrite_existing:
            return user, False

        update_data = {
            "email": user_create.email,
            "role": user_create.role,
            "is_active": user_create.is_active,
            "hashed_password": hash_password(user_create.password),
            "updated_at": datetime.now(timezone.utc),
        }
        await collection.update_one({"user_id": user.user_id}, {"$set": update_data})
        updated_user = await UserService.get_user_by_id(user.user_id)
        if not updated_user:
            raise RuntimeError(f"Could not reload seeded user '{user_create.username}' after update")
        logger.info("Seed user updated: %s (role: %s)", updated_user.username, updated_user.role)
        return updated_user, False
    
    @staticmethod
    async def get_user_by_id(user_id: str) -> Optional[UserInDB]:
        """
        Get a user by ID.
        
        Args:
            user_id: User identifier
        
        Returns:
            User model if found, None otherwise
        """
        collection = await UserService.get_user_collection()
        user_doc = await collection.find_one({"user_id": user_id})
        
        if user_doc:
            return UserInDB(**user_doc)
        return None
    
    @staticmethod
    async def get_user_by_username(username: str) -> Optional[UserInDB]:
        """
        Get a user by username.
        
        Args:
            username: Username to search for
        
        Returns:
            User model if found, None otherwise
        """
        collection = await UserService.get_user_collection()
        user_doc = await collection.find_one({"username": username})
        
        if user_doc:
            return UserInDB(**user_doc)
        return None
    
    @staticmethod
    async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username
            password: Plain text password
        
        Returns:
            User model if authentication successful, None otherwise
        """
        user = await UserService.get_user_by_username(username)
        
        if not user or not user.is_active:
            return None
        
        if not verify_password(password, user.hashed_password):
            logger.warning(f"Failed login attempt for user: {username}")
            return None
        
        logger.info(f"User authenticated: {username}")
        return user
    
    @staticmethod
    async def list_users(skip: int = 0, limit: int = 100) -> list[UserResponse]:
        """
        List all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
        
        Returns:
            List of user models
        """
        collection = await UserService.get_user_collection()
        cursor = collection.find({}).skip(skip).limit(limit)
        users = await cursor.to_list(length=limit)
        
        return [UserResponse(**doc) for doc in users]
    
    @staticmethod
    async def update_user(user_id: str, **kwargs) -> Optional[UserInDB]:
        """
        Update a user's information.
        
        Args:
            user_id: User identifier
            **kwargs: Fields to update
        
        Returns:
            Updated user model if successful, None otherwise
        """
        collection = await UserService.get_user_collection()
        
        update_data = {}
        for key, value in kwargs.items():
            if key in {"username", "email", "role", "is_active"}:
                update_data[key] = value
        
        if not update_data:
            return None
        
        result = await collection.update_one(
            {"user_id": user_id},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return None
        
        return await UserService.get_user_by_id(user_id)
    
    @staticmethod
    async def delete_user(user_id: str) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            True if user was deleted, False otherwise
        """
        collection = await UserService.get_user_collection()
        result = await collection.delete_one({"user_id": user_id})
        
        if result.deleted_count > 0:
            logger.info(f"User deleted: {user_id}")
            return True
        return False

