import hashlib
from dataclasses import dataclass

@dataclass
class TenantContext:
    """
    Represents the context of a tenant.

    This class is designed to encapsulate all relevant details about a tenant,
    including their unique client identifier, display name, and associated rate
    limit settings. It is primarily used to provide a structured representation
    of tenant-specific configurations which might be used in multi-tenant
    environments to enforce unique behaviors or rate limits based on the tenant.

    Attributes:
        client_id: A unique identifier assigned to the tenant.
        display_name: A human-readable name corresponding to the tenant.
        rate_limit_per_minute: The maximum number of requests this tenant is
            allowed to make per minute.
    """
    client_id: str
    display_name: str
    rate_limit_per_minute: int


async def validate_tenant_api_key(client_id: str, api_key: str, auth_db) -> dict | None:
    """
    Validates the provided API key for a given tenant identified by the client ID. This function
    authenticates a client using stored API key data from the authentication database and ensures
    that the client is active and the provided API key matches the stored hash.

    Parameters:
    client_id (str): The unique identifier for the tenant/client whose API key is being validated
    api_key (str): The API key provided by the client for authentication.
    auth_db: The authentication database connection interface used to perform tenant data lookups.

    Returns:
    dict | None: A dictionary containing tenant data if the API key validation is successful and the
    tenant is active. Returns None if validation fails or the tenant does not exist.
    """
    if not client_id or not api_key or auth_db is None:
        return None

    tenant_doc = await auth_db["authorized_telemetry_clients"].find_one({
        "client_id": client_id,
        "is_active": True
    })

    if not tenant_doc:
        return None

    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    stored_hash = tenant_doc.get("api_key_hash")

    if not stored_hash or api_key_hash != stored_hash:
        return None

    return tenant_doc