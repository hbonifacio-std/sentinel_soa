"""
A module implementing a MongoDB adapter for user repository operations.

This module contains the `MongoUserRepositoryAdapter` class, designed to interact
with a MongoDB database and perform CRUD operations on the "users" collection.
The adapter serves as an implementation of the `UserRepositoryPort` interface,
providing methods for retrieving, creating, and listing user records.

Classes:
    - MongoUserRepositoryAdapter: Implements user repository operations for a
      MongoDB database.
"""
import logging

from typing import List, Optional
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.ports.auth.user_repository_port import UserRepositoryPort
from core_orchestrator.domain.entities.auth.user import UserInDB

logger = logging.getLogger(__name__)


class MongoUserRepositoryAdapter(UserRepositoryPort):
    """
    Adapter class for user repository operations on a MongoDB database.

    This class implements the `UserRepositoryPort` interface, providing methods to
    interact with the "users" collection in a MongoDB database. It includes
    functionalities such as retrieving users by user ID, username, or email,
    creating new users, listing all users, and ensuring unique indexes.

    Attributes:
        collection: The MongoDB collection representing the "users" data.
    """
    def __init__(self, db_manager: DatabaseManager):
        """
        Initializes the class with a database manager and sets up the user's collection.

        Parameters:
            db_manager (DatabaseManager): The manager used to handle database operations.
        """
        self._db_manager = db_manager
        self.collection = db_manager.get_auth_db()["users"]


    async def get_user_user_id(self, use_id: str) -> Optional[UserInDB]:
        """
        Retrieves a user document by their user ID and returns it as a UserInDB instance.

        This method interacts with the database collection to find a user document matching
        the provided user ID. If a matching document is found, it is parsed and returned as
        a UserInDB object. If no document is found, the method returns None.

        Parameters:
            use_id (str): The unique identifier of the user to be retrieved.

        Returns:
            Optional[UserInDB]: An instance of UserInDB if a matching user document is found,
            otherwise None.
        """
        user_doc = await self.collection.find_one({"user_id": use_id})
        if user_doc:
            return UserInDB(**user_doc)
        return None



    async def get(self, user_id: str) -> Optional[UserInDB]:
        """
        Retrieves a user record by user ID from the database.

        This asynchronous method queries the database collection to fetch a user record
        matching the given user ID. The record, if found, is returned as a UserInDB
        object. If no record is found, the method returns None.

        Parameters:
        user_id (str): The unique identifier of the user to retrieve.

        Returns:
        Optional[UserInDB]: An instance of UserInDB if a user record matching the
        provided user ID is found. Returns None if no such record exists.
        """
        user_doc = await self.collection.find_one({"user_id": user_id})
        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        """
        Retrieve a user document from the database by username asynchronously.

        This method queries the collection for a document that matches the provided
        username and returns a UserInDB object constructed from the document if
        found. If no document is found, it returns None.

        Args:
            username (str): The username to the query in the collection.

        Returns:
            Optional[UserInDB]: A UserInDB instance if a document matching the
            username is found; otherwise, None.
        """
        user_doc = await self.collection.find_one({"username": username})

        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        """
        Retrieves a user document from the database by email.

        This asynchronous method attempts to fetch a user record matching the given
        email from the database. If a user document is found, it is converted into
        a `UserInDB` instance and returned. If no document is found, the method
        returns `None`.

        Parameters:
        email: str
            The email address of the user to retrieve.

        Returns:
        Optional[UserInDB]
            A `UserInDB` instance if a matching user document is found, otherwise `None`.

        """
        user_doc = await self.collection.find_one({"email": email})
        if user_doc:
            return UserInDB(**user_doc)
        return None

    async def create(self, user_create: UserInDB, hashed_password:str) -> UserInDB:
        """
        Asynchronously creates a new user in the database.

        This function takes in a user object, hashes the provided password, and inserts the
        user data into the database. It also logs the creation event with the username and
        assigned role of the user.

        Args:
            user_create (UserInDB): The user object containing user details such as
                                    username, email, role, etc.
            hashed_password (str): The hashed password string to be associated with
                                   the user.

        Returns:
            UserInDB: The newly created user object is populated with all relevant
                      attributes.
        """

        user_create.hashed_password = hashed_password

        await self.collection.insert_one(user_create.__dict__)
        logger.info(f"User created: {user_create.username} (role: {user_create.role})")

        return user_create

    async def list_all(self) -> List[UserInDB]:
        """
        Asynchronously retrieves all user documents from the database collection.

        This method fetches all users from the database, converts each document to a
        UserInDB object, and returns the list of UserInDB instances.

        Returns:
            List[UserInDB]: A list containing all users as UserInDB instances.
        """
        cursor = self.collection.find({})
        users = await cursor.to_list(length=None)
        return [UserInDB(**doc) for doc in users]

    async def ensure_indexes(self) -> None:
        """
        Ensure all required database indexes are created.

        Summary:
        Creates unique indexes on the "username" and "email" fields of the database
        collection to enforce uniqueness constraints. This method should be invoked
        during initialization to ensure the database schema meets indexing
        requirements.

        Raises:
            pymongo.errors.PyMongoError: If an error occurs while creating indexes.
        """
        await self.collection.create_index("username", unique=True)
        await self.collection.create_index("email", unique=True)
