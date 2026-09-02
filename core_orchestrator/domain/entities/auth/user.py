"""
User entities for authentication and authorization.

Defines the Pydantic entities for user representation, credentials, and tokens.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

@dataclass
class User:
    client_id: str
    username: str
    email: str
    role: str
    is_active: bool = True
    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None

    def __init__(
            self,
            client_id: str,
            username: str,
            email: str,
            role: str,
            user_id: str,
            is_active: bool = True,
            created_at: Optional[datetime] = None,
            **kwargs
    ):
        self.client_id = client_id
        self.username = username
        self.email = email
        self.role = role
        self.user_id = user_id or str(uuid.uuid4())
        self.is_active = is_active
        self.created_at = created_at or datetime.now(timezone.utc)

@dataclass
class UserInDB(User):
    hashed_password: str = ""

    def __init__(
            self, client_id: str,
            username: str, email: str,
            role: str, user_id: str,
            is_active: bool = True,
            created_at: Optional[datetime] = None,
            hashed_password: str = "", **kwargs):

        super().__init__(client_id, username, email, role, user_id, is_active, created_at, **kwargs)
        self.client_id = client_id
        self.username = username
        self.email = email
        self.hashed_password = hashed_password
        self.role = role
        self.user_id = user_id or str(uuid.uuid4())
        self.is_active = is_active
        self.created_at = created_at or datetime.now(timezone.utc)


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
