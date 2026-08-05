from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import ipaddress

from core_orchestrator.domain.exceptions.telemetry_exceptions import InvalidNetworkContextException, \
    InvalidHttpContextException, InvalidIPFormatException, InvalidLogTimestampException


@dataclass(frozen=True)
class NetworkContext:
    """
    Represents the network context for a client-server connection.

    This class encapsulates network-related details about a connection, including the
    client's IP address, port number, server port, and any proxy information. It is
    designed to provide validation for port numbers and support immutability by being
    a frozen dataclass.
    """
    client_ip: str
    client_port: Optional[int] = None
    server_port: Optional[int] = None
    proxy_forwarded_for: Optional[str] = None
    proxy_real_ip: Optional[str] = None

    def __post_init__(self):
        """
        Validates port values for client_port and server_port upon initialization.

        This method performs validation checks for the client_port and server_port attributes
        to ensure they fall within the valid range. If either port is specified but does not
        fall within the accepted range of 0 to 65,535 (inclusive), a ValueError is raised.

        Raises:
            ValueError: If client_port is not in the range 0-65535.
            ValueError: If server_port is not in the range 0-65535.
        """
        if self.client_port is not None and not (0 <= self.client_port <= 65535):
            raise InvalidNetworkContextException(
                f"client_port '{self.client_port}' must be between 0 and 65535."
            )
        if self.server_port is not None and not (0 <= self.server_port <= 65535):
            raise InvalidNetworkContextException(
                f"server_port '{self.server_port}' must be between 0 and 65535."
            )

    @property
    def has_proxy(self) -> bool:
        return bool(self.proxy_forwarded_for or self.proxy_real_ip)


@dataclass(frozen=True)
class HttpContext:
    method: str
    path: str
    status_code: int
    query: Optional[str] = None
    processing_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    response_size_bytes: Optional[int] = None
    payload: Optional[Any] = None

    def __post_init__(self):
        if not (100 <= self.status_code <= 599):
            raise InvalidHttpContextException(
                f"HTTP status code '{self.status_code}' is out of range (100-599)."
            )

    @property
    def is_error_status(self) -> bool:
        """
        Property that checks if the status code represents an error.

        This property evaluates whether the HTTP status code is in the range of
        400 and above, indicating a client or server error.

        Returns:
            bool: True if the status code is 400 or greater, otherwise False.
        """
        return self.status_code >= 400

    @property
    def is_server_error(self) -> bool:
        """
        Determines if the status code indicates a server error.

        A server error is identified when the HTTP status code
        is greater than or equal to 500. This property provides
        a convenient way to check for server errors in a response.

        Returns:
            bool: True if the status code is a server error
            (>= 500), otherwise False.
        """
        return self.status_code >= 500


@dataclass(frozen=True)
class SecurityContext:
    """
    Represents the security context of a user session.

    This class encapsulates information about the security context of a user, including
    details about authentication status, login attempts, and the authentication
    mechanism used. It provides methods to easily evaluate the state of authentication
    and login attempts. This class is immutable.
    """
    authenticated_user: Optional[str] = None
    attempted_login_user: Optional[str] = None
    auth_mechanism: Optional[str] = None

    @property
    def is_login_attempt(self) -> bool:
        """
        Check if a login attempt has been made.

        This property evaluates whether there exists an attempted login by checking
        if the `attempted_login_user` attribute is not None.

        Returns:
            bool: True if a login attempt has been made, False otherwise.
        """
        return self.attempted_login_user is not None

    @property
    def is_authenticated(self) -> bool:
        """
        Checks if the user is authenticated.

        This property determines whether the user is authenticated by checking
        if an authenticated_user is set.

        Returns:
            bool: True if the user is authenticated, False otherwise.
        """
        return self.authenticated_user is not None


@dataclass(frozen=True)
class HostContext:
    """
        Represents the context of a host process.

        This class is a data structure that holds information about a host process,
        including the process ID, name, total runtime in milliseconds, and the
        environment in which it is executing. The purpose of this class is to provide
        a structured way to track and access key details about the host process.

    """
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_time_ms: Optional[float] = None
    environment: Optional[str] = None


@dataclass
class LogEvent:
    """
    Represents a log event containing various contextual information.

    This class is used to model and encapsulate data related to a logging event, including
    details such as the source IP address, timestamp, and various domain-specific contexts
    like network, HTTP, security, host, and infrastructure information. It includes
    methods for determining suspicious logs and associating logs with specific environments.

    Attributes:
        source_ip: The source IP address from which the event originated.
        timestamp_utc: The UTC timestamp when the event occurred.
        client_id: An optional unique identifier for the client generating the event.
        source_id: An optional identifier for the source system emitting the event.
        network: Optional network-related contextual information.
        http: Optional HTTP-related contextual information.
        security: Optional security-related contextual information.
        host: Optional host-specific contextual information.
        extra_fields: A dictionary for capturing additional unspecified fields.

    Raises:
        ValueError: If the provided source_ip is not in a valid IP address format or if
            the timestamp is not specified in UTC.
    """
    source_ip: str
    timestamp_utc: datetime
    client_id: Optional[str] = None
    source_id: Optional[str] = None
    network: Optional[NetworkContext] = None
    http: Optional[HttpContext] = None
    security: Optional[SecurityContext] = None
    host: Optional[HostContext] = None
    extra_fields: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """
        Validates and processes the initialization of an instance.

        This function performs two primary checks during instance initialization. First,
        it ensures that the provided IP address is in a valid format. If the IP format is
        invalid, a ValueError is raised. Second, it ensures that the timestamp is in UTC.
        If no timezone information is provided, the timestamp is converted to UTC time.

        Raises:
            ValueError: If the provided IP address has an invalid format.
        """
        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError:
            raise InvalidIPFormatException(self.source_ip)

        if self.timestamp_utc.tzinfo is None:
            self.timestamp_utc = self.timestamp_utc.replace(tzinfo=timezone.utc)

        if self.timestamp_utc > datetime.now(timezone.utc):
            raise InvalidLogTimestampException(str(self.timestamp_utc))



    @property
    def is_suspicious_event(self) -> bool:
        """
        Determines whether the event is considered suspicious based on its HTTP and Security attributes.

        Summary:
        This property evaluates the HTTP and Security aspects of an event to determine if it meets the
        criteria for being flagged as suspicious. An event is flagged suspicious if:
        1. It has an associated HTTP object with an error status.
        2. It relates to a login attempt in the Security object but lacks proper authentication.

        Returns:
            bool: True if the event is deemed suspicious, otherwise False.
        """
        if self.http and self.http.is_error_status:
            return True
        if self.security and self.security.is_login_attempt and not self.security.is_authenticated:
            return True
        return False

    def is_from_environment(self, env_name: str) -> bool:
        """
        Determines if the current host environment matches the specified environment name.

        This method checks whether the environment name associated with the host matches
        the given environment name. The comparison is case-insensitive.

        Arguments:
        env_name (str): The name of the environment to compare against.

        Returns:
        bool: True if the host's environment matches the given name, otherwise False.
        """
        if self.host and self.host.environment:
            return self.host.environment.lower() == env_name.lower()
        if self.host and self.host.environment:
            return self.host.environment.lower() == env_name.lower()
        return False