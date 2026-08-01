from core_orchestrator.domain.exceptions.domain_exceptions import DomainException


class AuthException(DomainException):
    """Base authentication exception."""
    pass

class InvalidCredentialsError(AuthException):
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message)

class UserInactiveError(AuthException):
    def __init__(self, user_id: str):
        super().__init__(f"User {user_id} is inactive")

class UserAlreadyExistsError(AuthException):
    def __init__(self, field: str, value: str):
        super().__init__(f"user with the {field} '{value}' is invalid.")

class InvalidTokenError(AuthException):
    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message)

class TokenRevokedError(AuthException):
    def __init__(self, message: str = "The presented token has been revoked."):
        super().__init__(message)