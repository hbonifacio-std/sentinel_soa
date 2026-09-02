from core_orchestrator.domain.exceptions.domain_exceptions import DomainException


class InvalidNetworkContextException(DomainException):
    """
    Exception raised for violations in the network context domain.

    This exception is used to indicate specific invalid states or operations
    within the network context. It provides a custom error message, code, and
    status code to facilitate identification and handling of such errors.

    arg:
        detail (str): Additional detail about the specific reason for the
        exception.
    """
    def __init__(self, detail: str):
        super().__init__(
            message=f"Network context domain violation: {detail}",
            code="INVALID_NETWORK_CONTEXT",
            status_code=400
        )

class UnresolvableClientIPException(DomainException):
    """
    Represents an exception raised when a valid client IP address cannot be resolved.

    This exception is used to signify that the source of a request lacks a resolvable
    or valid client IP address. It provides contextual information such as the source
    identifier and a predefined error code and status code.

    arg:
        source_id: str
            Identifier of the source for which the client IP address could
            not be resolved. Defaults to "Unknown".
    """
    def __init__(self, source_id: str = "Unknown"):
        super().__init__(
            message=f"Unable to resolve valid client IP address for source '{source_id}'.",
            code="UNRESOLVABLE_CLIENT_IP",
            status_code=422
        )

class InvalidHttpStatusException(DomainException):
        """
        Exception raised for invalid HTTP status codes in the domain context.

        This exception is used to indicate that a provided HTTP status code is considered
        invalid within the specific domain constraints. It extends the DomainException
        class and provides a detailed message indicating the invalid status code.
        """

        def __init__(self, status_code: int):
            super().__init__(
                message=f"HTTP status code '{status_code}' is invalid in domain context.",
                code="INVALID_HTTP_STATUS",
                status_code=400
        )

class HttpPayloadCorruptedException(DomainException):
        """
        Exception raised when an HTTP payload cannot be processed.

        This exception is used to indicate that an issue occurred while handling an HTTP
        payload, rendering it corrupted or invalid. It includes a specific reason for the
        corruption to help with debugging and error handling.
        """

        def __init__(self, reason: str):
            super().__init__(
                message=f"HTTP payload could not be processed: {reason}",
                code="CORRUPTED_HTTP_PAYLOAD",
                status_code=422
        )

class UnauthorizedEventException(DomainException):
        """
        Exception for unauthorized event handling in the security domain.

        This exception is raised when a user attempts to perform an action that
        requires authentication or proper authorization within the security domain. It is
        used to enforce access control and signal that authorization is necessary to
        proceed. Typically, this would occur in scenarios where logging or sensitive
        actions are being performed without prior authentication.

        Attributes:
            user: str
                The name of the user associated with the unauthorized event.
        """

        def __init__(self, user: str = "Anonymous"):
            super().__init__(
                message=f"Security domain violation for user '{user}': authentication required.",
                code="UNAUTHORIZED_LOG_EVENT",
                status_code=401
        )

class SuspiciousActivityDetectedException(DomainException):
        """
        Exception raised to indicate that a specific suspicious activity rule has been triggered.

        This exception is used to handle cases where certain security or anomaly detection
        conditions are met, which may indicate potentially harmful or unauthorized actions.
        It provides information about the specific rule that was triggered and serves as
        a mechanism for securely halting further processing or triggering security processes.

        arg:
            reason (str): The specific reason or rule that triggered this exception.
        """

        def __init__(self, reason: str):
            super().__init__(
                message=f"Suspicious activity rule triggered: {reason}",
                code="SUSPICIOUS_ACTIVITY_DETECTED",
                status_code=403
        )

class InvalidLogEventTimestampException(DomainException):
        """
        Exception raised for invalid log event timestamps.

        This class represents an exception that occurs when a log event contains a
        timestamp that is deemed to be invalid because it is either set in the future
        or has already expired beyond an acceptable domain range.
        """

        def __init__(self, timestamp: str):
            super().__init__(
                message=f"Log event timestamp '{timestamp}' is out of acceptable domain range (future or expired).",
                code="INVALID_LOG_TIMESTAMP",
                status_code=422
        )

class MissingTenantContextException(DomainException):
        """
        Exception raised when a tenant identifier ('client_id') is missing.

        This exception is used to indicate that a required tenant identifier is
        absent during multi-tenant analysis operations. It is intended to prevent
        further processing and notify the caller of the missing context.
        """

        def __init__(self):
            super().__init__(
                message="Tenant identifier ('client_id') is mandatory for multi-tenant analysis operations.",
                code="MISSING_TENANT_CONTEXT",
                status_code=400
        )

class InvalidHttpContextException(DomainException):
        """
        Represents an exception raised when there is a violation of HTTP context.

        This exception is used to indicate that an operation or request has violated
        the expected HTTP context. It provides specific details about the violation,
        along with relevant error codes and HTTP response status.

        Args:
            detail: A string providing additional details about the HTTP context
                    violation.
        """
        def __init__(self, detail: str):
            super().__init__(
                message=f"HTTP context violation: {detail}",
                code="INVALID_HTTP_CONTEXT",
                status_code=400
        )

class InvalidIPFormatException(DomainException):
    def __init__(self, ip: str):
        super().__init__(
            message=f"Invalid IP address format: '{ip}'",
            code="INVALID_IP_FORMAT",
            status_code=422
        )


class InvalidLogTimestampException(DomainException):
    def __init__(self, timestamp: str):
        super().__init__(
            message=f"Log timestamp '{timestamp}' cannot be in the future.",
            code="INVALID_LOG_TIMESTAMP",
            status_code=422
        )