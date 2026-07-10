from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def mask_secret(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{'*' * (len(value) - 4)}{value[-4:]}"


class TelemetryClientBase(BaseModel):
    client_id: str = Field(..., min_length=3, max_length=120)
    display_name: str = Field(..., min_length=3, max_length=150)
    description: Optional[str] = None
    is_active: bool = True


class TelemetryClientCreate(TelemetryClientBase):
    api_key: str = Field(..., min_length=16, max_length=200)
    hmac_public_key: str = Field(..., min_length=3, max_length=120)
    hmac_secret: str = Field(..., min_length=16, max_length=200)


class TelemetryClientInDB(TelemetryClientBase):
    api_key: str
    hmac_public_key: str
    hmac_secret: str
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Config:
        from_attributes = True


class TelemetryClientResponse(TelemetryClientBase):
    hmac_public_key: str
    api_key_hint: str
    hmac_secret_hint: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_db_model(cls, client: TelemetryClientInDB) -> "TelemetryClientResponse":
        return cls(
            client_id=client.client_id,
            display_name=client.display_name,
            description=client.description,
            is_active=client.is_active,
            hmac_public_key=client.hmac_public_key,
            api_key_hint=mask_secret(client.api_key),
            hmac_secret_hint=mask_secret(client.hmac_secret),
            created_at=client.created_at,
            updated_at=client.updated_at,
        )


class TelemetryClientAuthContext(BaseModel):
    client_id: str
    display_name: str
    hmac_public_key: Optional[str] = None


class TelemetryBootstrapSummary(BaseModel):
    users_created: int = 0
    users_skipped: int = 0
    users_updated: int = 0
    clients_created: int = 0
    clients_skipped: int = 0
    clients_updated: int = 0
    rules_seeded: bool = False
    cache_warmed_clients: int = 0
