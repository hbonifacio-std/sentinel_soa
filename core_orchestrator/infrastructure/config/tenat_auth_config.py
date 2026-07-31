from pydantic import BaseModel, Field


class TenantAuthConfig(BaseModel):
    enforce_auth: bool = Field(default=False, alias="ENFORCE_TENANT_AUTH")
    default_rate_limit: int = Field(default=60, alias="DEFAULT_TENANT_RATE")