class DatabaseError(Exception):
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