"""
Password hashing and verification utilities.

Provides secure password hashing using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> str:
    """
    Hash a password using the native bcrypt library.

    Args:
        password: Plain text password

    Returns:
        Hashed password as a string (utf-8)
    """
    # 1. Convertir el string a bytes (exigido por bcrypt)
    password_bytes = password.encode('utf-8')

    # 2. Generar el salt y el hash
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)

    # 3. Retornar como string para que lo guardes fácil en tu base de datos
    return hashed_bytes.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password using native bcrypt.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Previously hashed password string

    Returns:
        True if password matches, False otherwise
    """
    try:
        # Convertir ambos a bytes para la comparación
        plain_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')

        # bcrypt.checkpw compara de forma segura contra ataques de temporización
        return bcrypt.checkpw(plain_bytes, hashed_bytes)
    except Exception:
        # En caso de que el hash guardado esté corrupto o malformado
        return False
