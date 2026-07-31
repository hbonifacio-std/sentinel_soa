from pydantic import BaseModel, EmailStr, Field

class UserCreateDTO(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = "user"

class UserResponseDTO(BaseModel):
    user_id: str
    username: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True

class TokenResponseDTO(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    user: UserResponseDTO

class TokenPayloadDto(BaseModel):
    """JWT token payload representation."""
    sub: str  # user_id
    username: str
    role: str
    exp: int  # expiration timestamp
    jti: str | None = None