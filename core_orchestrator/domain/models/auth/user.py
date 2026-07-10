"""
User models for authentication and authorization.

Defines the Pydantic models for user representation, credentials, and tokens.
"""

from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field, EmailStr


class UserBase(BaseModel):
    """Base user model with common fields."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: Literal["admin", "analyst", "viewer"] = Field(default="viewer")
    is_active: bool = Field(default=True)
    client_id: str | None = Field(default=None, description="Tenant ID this user belongs to")


class UserCreate(UserBase):
    """User creation model with password."""
    password: str = Field(..., min_length=8, max_length=100)


class UserInDB(UserBase):
    """User model as stored in database."""
    user_id: str
    hashed_password: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        from_attributes = True


class UserResponse(UserBase):
    """User response model (without password)."""
    user_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    client_api_key: str | None = Field(default=None, description="API key for the user's tenant (for direct API calls)")


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str  # user_id
    username: str
    role: str
    exp: int  # expiration timestamp
    jti: str | None = None

