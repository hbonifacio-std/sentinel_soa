"""
Tenant models for multi-tenancy support.

Defines the Pydantic models for tenant representation and management.
Tenants can optionally have telemetry client capabilities (API key + HMAC keys).
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class TenantBase(BaseModel):
    """Base tenant model with common fields."""
    client_id: str = Field(..., min_length=1, max_length=100, description="Unique tenant identifier")
    display_name: str = Field(..., min_length=1, max_length=200, description="Human-readable tenant name")
    description: Optional[str] = Field(default=None, description="Optional: description of tenant/source")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000, description="API rate limit per minute")
    is_active: bool = Field(default=True, description="Whether the tenant is active")


class TenantCreate(BaseModel):
    """Tenant creation model - only accepts basic info, keys are auto-generated."""
    client_id: str = Field(..., min_length=1, max_length=100, description="Unique tenant identifier")
    display_name: str = Field(..., min_length=1, max_length=200, description="Human-readable tenant name")
    description: Optional[str] = Field(default=None, description="Optional: description of tenant/source")


class TenantInDB(TenantBase):
    """Tenant model as stored in database."""
    api_key_hash: Optional[str] = Field(default=None, description="Bcrypt hash of tenant API key")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        from_attributes = True


class TenantResponse(TenantBase):
    """Tenant response model (without sensitive data)."""
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TenantResponseWithKey(TenantResponse):
    """Tenant response with API key (only returned at creation)."""
    api_key_plaintext: Optional[str] = Field(default=None, description="API key (only shown once)")
