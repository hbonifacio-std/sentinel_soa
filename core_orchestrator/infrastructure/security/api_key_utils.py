"""
API Key hashing utilities using bcrypt.

Provides secure hashing and verification for API keys with bcrypt,
which is significantly more resistant to brute force attacks than SHA256.
"""

import bcrypt
import logging
from typing import Optional

logger = logging.getLogger("core_orchestrator.security.api_key_utils")


def hash_api_key(api_key: str, rounds: int = 12) -> str:
    """
    Hash an API key using bcrypt with high security settings.
    
    Args:
        api_key: The plaintext API key to hash
        rounds: Cost factor for bcrypt (default 12 is secure)
               Higher = more secure but slower
               Range: 4-31 (recommended: 12-14)
    
    Returns:
        Hashed API key (can be safely stored in database)
    
    Raises:
        ValueError: If api_key is invalid
    """
    if not api_key or not isinstance(api_key, str):
        raise ValueError("API key must be a non-empty string")
    
    if len(api_key) < 32:
        raise ValueError("API key must be at least 32 characters")
    
    # Generate salt and hash
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(api_key.encode(), salt)
    
    logger.debug("API key hashed with bcrypt (rounds=%d)", rounds)
    return hashed.decode()


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """
    Verify that a plaintext API key matches its hash.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        api_key: The plaintext API key to verify
        api_key_hash: The stored hash to verify against
    
    Returns:
        True if key matches, False otherwise
    """
    if not api_key or not api_key_hash:
        logger.warning("Empty API key or hash provided for verification")
        return False
    
    try:
        # bcrypt.checkpw is constant-time and safe
        return bcrypt.checkpw(api_key.encode(), api_key_hash.encode())
    except Exception as e:
        logger.error(f"Error during API key verification: {e}")
        return False


def migrate_sha256_to_bcrypt(sha256_hash: str) -> Optional[str]:
    """
    Migrate from SHA256 hashing to bcrypt.
    
    NOTE: This function cannot directly migrate existing SHA256 hashes.
    Instead, it serves as a marker for the migration process:
    
    1. During login/key verification, detect old SHA256 hashes
    2. Ask user to provide plaintext key (during re-auth)
    3. Re-hash with bcrypt and update database
    4. Return None to force re-hashing
    
    Args:
        sha256_hash: Old SHA256 hash (for identification)
    
    Returns:
        None (indicates old format, re-hashing required)
    """
    logger.warning(
        "Detected SHA256 hash format. "
        "Migration to bcrypt required on next authentication."
    )
    return None


def is_bcrypt_hash(hash_string: str) -> bool:
    """
    Check if a hash string is in bcrypt format.
    
    Bcrypt hashes start with '$2a$', '$2b$', or '$2y$'.
    
    Args:
        hash_string: The hash to check
    
    Returns:
        True if bcrypt format, False otherwise
    """
    return hash_string.startswith(('$2a$', '$2b$', '$2y$'))


def is_sha256_hash(hash_string: str) -> bool:
    """
    Check if a hash string is in SHA256 format.
    
    SHA256 hashes are 64 hex characters.
    
    Args:
        hash_string: The hash to check
    
    Returns:
        True if SHA256 format, False otherwise
    """
    return len(hash_string) == 64 and all(c in '0123456789abcdef' for c in hash_string.lower())
