
class ConfigurationError(Exception):
    """Base exception for all configuration-related errors."""
    pass


class MissingEnvironmentVariableError(ConfigurationError):
    """Raised when a required environment variable is missing or empty."""

    def __init__(self, variable_name: str, message: str | None = None):
        self.variable_name = variable_name
        default_message = f"Required environment variable '{variable_name}' is missing or empty."
        super().__init__(message or default_message)


class InvalidEnvironmentVariableError(ConfigurationError):
    """Raised when an environment variable value fails validation rules."""

    def __init__(self, variable_name: str, current_value: str, reason: str):
        self.variable_name = variable_name
        self.current_value = current_value
        self.reason = reason
        message = (
            f"Invalid value '{current_value}' provided for environment variable '{variable_name}'. "
            f"Reason: {reason}"
        )
        super().__init__(message)