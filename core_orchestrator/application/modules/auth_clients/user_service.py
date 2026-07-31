import logging
import uuid

from core_orchestrator.domain.entities.auth import UserInDB
from core_orchestrator.domain.entities.auth.user import User
from core_orchestrator.domain.exceptions.auth_exceptions import UserAlreadyExistsError, UserInactiveError, InvalidCredentialsError
from core_orchestrator.domain.ports import UserRepositoryPort, PasswordHasherPort
from core_orchestrator.infrastructure.dto.auth.auth_dto import UserCreateDTO, UserResponseDTO

logger = logging.getLogger(__name__)

class UserService:
    def __init__(self, user_repository: UserRepositoryPort, password_hasher: PasswordHasherPort):
        self._user_repository = user_repository
        self._password_hasher = password_hasher

    async def create_user(self, dto: UserCreateDTO, client_id: str) -> UserResponseDTO:
        if await self._user_repository.get_by_username(dto.username):
            raise UserAlreadyExistsError(field="username", value=dto.username)

        if await self._user_repository.get_by_email(dto.email):
            raise UserAlreadyExistsError(field="email", value=dto.email)

        hashed_password = self._password_hasher.hash_password(dto.password)
        saved_user: User = await self._user_repository.create(
            UserInDB(
                user_id=str(uuid.uuid4()),
                username=dto.username,
                email=dto.email,
                role=dto.role,
                client_id=client_id,
                hashed_password=hashed_password,
                is_active=True
            ),
            hashed_password=hashed_password
        )
        return UserResponseDTO.model_validate(saved_user)

    async def get_by_username(self, username: str) -> UserResponseDTO:
        user = await self._user_repository.get_by_username(username)
        if not user:
            raise InvalidCredentialsError("User not found")
        if not user.is_active:
            raise UserInactiveError(user_id=username)
        return UserResponseDTO.model_validate(user)

    async def get_by_user_id(self, user_id: str) -> UserResponseDTO:
        user = await self._user_repository.get_user_user_id(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")
        if not user.is_active:
            raise UserInactiveError(user_id=user_id)
        return UserResponseDTO.model_validate(user)

    async def authenticate_user(self, username: str, password: str) -> UserResponseDTO:
        user = await self._user_repository.get_by_username(username)

        if not user or not self._password_hasher.verify_password(password, user.hashed_password):
            logger.warning(f"Failed login attempt for: {username}")
            raise InvalidCredentialsError()

        if not user.is_active:
            raise UserInactiveError(user_id=user.user_id)

        logger.info(f"User successfully authenticated: {username}")
        return UserResponseDTO.model_validate(user)