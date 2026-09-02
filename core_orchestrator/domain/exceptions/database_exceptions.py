from core_orchestrator.domain.exceptions.domain_exceptions import DomainException


class DatabaseError(DomainException):
    """Base exception for all errors related to database infrastructure."""
    def __init__(self, message: str = "Database error occurred."):
        self.message = message
        super().__init__(self.message)


class DatabaseNotConnectedError(DatabaseError):
    """It is thrown when an attempt is made to perform an operation without having initialized the client (AsyncMongoClient / Redis)."""
    def __init__(self, client_name: str = "MongoDB"):
        self.client_name = client_name
        self.message = f"{self.client_name} client is not connected. Make sure to call connect() first."
        super().__init__(self.message)


class DatabaseConnectionFailedError(DatabaseError):
    """It is triggered when the initial attempt to establish a physical connection to the driver/server fails."""
    def __init__(self, service_name: str, details: str):
        self.service_name = service_name
        self.details = details
        self.message = f"Failed to initialize connection to {self.service_name}: {self.details}"
        super().__init__(self.message)


class DatabaseOperationError(DomainException):
    """
    Represents an error that occurs during a database operation.

    This exception is specifically designed to handle errors related to database
    operations and provides meaningful information about the operation that
    triggered the error and any additional details.

    Args:
        operation: str
            The name or type of database operation where the error occurred.
        detail: str
            Additional details about the error, if available.
    """
    def __init__(self, operation: str, detail: str = ""):
        message = f"Error performing database operation [{operation}]."
        if detail:
            message += f" Details: {detail}"
        super().__init__(message=message, code="DATABASE_OPERATION_ERROR")