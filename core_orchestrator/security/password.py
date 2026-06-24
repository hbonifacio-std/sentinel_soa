"""
Password hashing and verification utilities.

Provides secure password hashing using bcrypt.
"""

from passlib.context import CryptContext

# Configure bcrypt password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
    
    Returns:
        Hashed password
    
    Note:
        Bcrypt has a 72-byte limit. Passwords longer than this are truncated.
    """
    # Bcrypt has a 72-byte limit for the password. Truncate if necessary.
    # This ensures compatibility with bcrypt limitations.
    truncated_password = password[:72]
    return pwd_context.hash(truncated_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Previously hashed password
    
    Returns:
        True if password matches, False otherwise
    
    Note:
        Bcrypt has a 72-byte limit. Passwords longer than this are truncated
        to match the hash_password behavior.
    """
    # Apply the same truncation as hash_password to ensure consistency
    truncated_password = plain_password[:72]
    return pwd_context.verify(truncated_password, hashed_password)

