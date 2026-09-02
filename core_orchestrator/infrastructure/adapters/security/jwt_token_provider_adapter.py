"""
Concrete JWT token service adapter for the application layer.
"""

from datetime import timedelta
from typing import Optional, Dict, Any

from core_orchestrator.domain.ports.auth.token_manager_port import TokenProviderPort
from core_orchestrator.infrastructure.adapters.security.jwt_utils import (
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    get_token_jti,
)


class JwtTokenProviderAdapter(TokenProviderPort):
    """
    Adapter class for managing JSON Web Token (JWT) operations.

    This class provides methods to create and validate access and refresh tokens for
    authentication purposes. It serves as an adapter to integrate with a concrete
    JWT-based implementation and facilitates token generation, validation, and JTI
    extraction.

    Methods:
        create_access_token: Generates an access token with specific details
            such as user information and roles. Supports custom expiration.
        create_refresh_token: Generates a refresh token tied to the user with an
            optional expiration period.
        verify_refresh_token: Validates a given refresh token, verifying its
            structure and claims.
        get_token_jti: Extracts the JWT ID (JTI) from a given token.
    """

    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None,
    ) -> tuple[str, str]:
        """
        Generates an access token for a user.

        The function creates a JSON Web Token (JWT) that includes the user's
        identification details and role. The token can optionally have an expiration
        time, specified by the `expires_delta` argument.

        Arguments:
            user_id: The unique identifier of the user for whom the token is generated.
            username: The username associated with the user.
            role: The role assigned to the user (e.g., admin, user).
            expires_delta: Optional timedelta defining the token's expiration period.
                If not provided, the token will have a default expiration.

        Returns:
            A tuple containing the access token as a string and its expiration as a
            string in ISO format.
        """
        return create_access_token(
            user_id=user_id,
            username=username,
            role=role,
            expires_delta=expires_delta,
        )

    def create_refresh_token(
        self,
        user_id: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Generates a refresh token for a user with an optional expiration time.

        This function generates a secure refresh token, which can be used for
        refreshing access tokens in an authentication system. It allows for
        an optional expiration time to be specified; if no expiration is provided,
        a default expiration time will be used.

        Args:
            user_id: The unique identifier of the user for whom the refresh token
                is being generated.
            expires_delta: An optional timedelta specifying the duration for which
                the token will remain valid. If not provided, a default expiration
                time is used.

        Returns:
            A string representing the generated refresh token.
        """
        return create_refresh_token(
            user_id=user_id,
            expires_delta=expires_delta,
        )

    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifies the validity of a provided refresh token and returns associated
        data if the token is valid.

        Parameters:
        token: str
            The refresh token to be verified.

        Returns:
        Optional[Dict[str, Any]]
            A dictionary containing associated data if the token is valid, or None
            if the token is invalid or expired.
        """
        return verify_refresh_token(token)

    def get_token_jti(self, token: str) -> Optional[str]:
        """
        Retrieves the JTI (JWT ID) from a given token.

        The method extracts the unique identifier (JTI) embedded in a JWT
        (JSON Web Token) to track or manage the specific token.

        Args:
            token (str): The token from which to extract the JTI.

        Returns:
            Optional[str]: The JTI value as a string if extraction is
            successful; otherwise, None.
        """
        return get_token_jti(token)

