"""
Tenant models for multi-tenancy support.

Defines the Pydantic models for tenant representation and management.
Tenants can optionally have telemetry client capabilities (API key + HMAC keys).
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class TenantBase(BaseModel):
    """Base tenant model with common fields."""
    tenant_id: str = Field(..., min_length=1, max_length=100, description="Unique tenant identifier")
    display_name: str = Field(..., min_length=1, max_length=200, description="Human-readable tenant name")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000, description="API rate limit per minute")
    is_active: bool = Field(default=True, description="Whether the tenant is active")
    
    # Telemetry client fields (optional - tenant can be a telemetry source)
    client_id: Optional[str] = Field(default=None, description="Optional: client ID if this tenant is a telemetry source")
    source_id: Optional[str] = Field(default=None, description="Optional: source ID for telemetry ingestion")
    description: Optional[str] = Field(default=None, description="Optional: description of tenant/source")
    api_key: Optional[str] = Field(default=None, description="Optional: API key for telemetry ingestion")
    hmac_public_key: Optional[str] = Field(default=None, description="Optional: public key for HMAC verification")
    hmac_secret: Optional[str] = Field(default=None, description="Optional: secret key for HMAC verification")


class TenantCreate(TenantBase):
    """Tenant creation model."""
    pass


class TenantInDB(TenantBase):
    """Tenant model as stored in database."""
    api_key_hash: Optional[str] = Field(default=None, description="SHA256 hash of tenant API key (different from telemetry api_key)")
    api_key_plaintext: Optional[str] = Field(default=None, description="Plaintext API key (only shown at creation)")
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
