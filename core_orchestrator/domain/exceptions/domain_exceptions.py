from typing import Sequence


class DomainException(Exception):
    """
    Exception representing domain-specific errors.

    This class serves as a base for domain-related exceptions and includes
    both a message and an optional error code to help identify specific error
    conditions within the domain context.
    """
    def __init__(self, message: str, code: str = "DOMAIN_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class InvalidProviderException(DomainException):
    """
    Exception raised when an invalid provider is specified.

    This exception is used to indicate that the specified provider is not one of
    the allowed valid providers. It provides a detailed error message and a specific
    error code to help identify the issue.
    """

    def __init__(self, provider: str, valid_providers: Sequence[str]):
        allowed_str = ", ".join(f"'{p}'" for p in valid_providers)
        super().__init__(
            message=f"The AI provider '{provider}' is invalid. The supported providers are: {allowed_str}.",
            code="INVALID_PROVIDER"
        )

class ModelNotFoundError(DomainException):
    """
    Exception raised when an AI Model or Provider is not found.

    This exception is used to indicate that a requested AI Model or
    Provider does not exist or is unavailable in the system. It inherits
    from the base DomainException to align with domain-specific error
    handling.

    Args:
        model_or_provider: The name of the AI Model or Provider that was
            not found.
    """
    def __init__(self, model_or_provider: str):
        super().__init__(
            message=f"AI Model or Provider '{model_or_provider}' was not found.",
            code="MODEL_NOT_FOUND"
        )


class MongoTranslatorNotConfiguredException(DomainException):
    """
    Exception raised when the default MongoDB translator model is not configured for a specific tenant.

    This exception is specific to scenarios where a MongoDB translator model has not been correctly
    set up for a given tenant identified by a client ID. It provides a specific error code and
    message to indicate the nature of the misconfiguration.

    Args:
        client_id (str): Identifier for the tenant or client for which the MongoDB translator model
        has not been configured.
    """
    def __init__(self, client_id: str):
        super().__init__(
            message=f"Default MongoDB translator model is not configured for tenant '{client_id}'.",
            code="MONGO_TRANSLATOR_NOT_CONFIGURED"
        )

class TenantNotFoundException(DomainException):
    """
    Exception raised when a tenant associated with the given client ID is not found.

    This exception is specifically used in scenarios where operations depend on
    the existence of a tenant, and no tenant corresponds to the provided client ID.
    It inherits from DomainException to provide a standardized way of handling
    domain-specific errors.
    """
    def __init__(self, client_id: str):
        super().__init__(
            message=f"Tenant '{client_id}' was not found.",
            code="TENANT_NOT_FOUND"
        )


class ModelNotAvailableException(DomainException):
    """
    Exception raised when a requested model is not available for a specific tenant.

    This exception is used to signal that the model identified by the provided
    model ID has not been configured or is unavailable for the client associated
    with the specified client ID. It extends the DomainException base class
    and provides a specific error code and message related to the unavailability
    of the requested model.

    Args:
        model_id: The identifier of the model that is unavailable.
        client_id: The identifier of the client requesting the unavailable model.
    """
    def __init__(self, model_id: str, client_id: str):
        super().__init__(
            message=f"Model '{model_id}' is not configured for tenant '{client_id}'.",
            code="MODEL_NOT_AVAILABLE"
        )


class ModelDisabledException(DomainException):
    """Exception raised when attempting to access a disabled model.

    This exception is used to indicate that a specific model is disabled for a
    particular tenant. It provides information about the disabled model's ID
    and the tenant's client ID causing the restriction.

    Args:
        model_id: The identifier of the disabled model.
        client_id: The identifier of the tenant attempting access.
    """
    def __init__(self, model_id: str, client_id: str):
        super().__init__(
            message=f"Model '{model_id}' is currently disabled for tenant '{client_id}'.",
            code="MODEL_DISABLED"
        )