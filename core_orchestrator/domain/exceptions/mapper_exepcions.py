from core_orchestrator.domain.exceptions.domain_exceptions import DomainException


class DeserializationException(DomainException):
    """
    Exception raised when an error occurs during the deserialization process.

    This exception is used to indicate issues when mapping data to a specific
    target class during deserialization. It provides details about the target
    class and the reason for the failure.

    Args:
        target_cls_name (str): The name of the target class where deserialization
            was attempted
        reason (str): The specific reason or details of the deserialization failure
    """
    def __init__(self, target_cls_name: str, reason: str):
        super().__init__(
            message=f"Error mapping data to '{target_cls_name}': {reason}",
            code="DESERIALIZATION_ERROR"
        )
