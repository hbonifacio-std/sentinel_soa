"""
Password hashing and verification utilities.

Provides secure password hashing using bcrypt.
"""
import logging

import bcrypt

from core_orchestrator.domain.ports import PasswordHasherPort

logger = logging.getLogger(__name__)
class PasswordHasherAdapter(PasswordHasherPort):

    def hash_password(self, password: str) -> str:
        """
        Hashes a plaintext password using the bcrypt algorithm.

        This function securely hashes a given password using the bcrypt
        algorithm. It first encodes the plaintext password into bytes, generates
        a cryptographically secure salt, and hashes the password along with
        the salt. The result is returned as a string.

        Args:
            password (str): The plaintext password to be hashed.

        Returns:
            str: The hashed password as a string.
        """

        password_bytes = password.encode('utf-8')

        salt = bcrypt.gensalt()
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)

        return hashed_bytes.decode('utf-8')


    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies if a plaintext password matches a hashed password.

        This function takes a plaintext password and a hashed password as input
        and checks if the plaintext password corresponds to the hashed one. It
        returns a boolean indicating the success or failure of the verification.

        It provides an additional safeguard by catching any unexpected errors
        and returning False if such an error occurs during the process.

        Parameters:
        plain_password: str
            The plaintext password to verify.
        hashed_password: str
            The hashed password used for verification.

        Returns:
        bool
            True if the plaintext password matches the hashed password, otherwise False.
        """
        try:
            plain_bytes = plain_password.encode('utf-8')
            hashed_bytes = hashed_password.encode('utf-8')

            return bcrypt.checkpw(plain_bytes, hashed_bytes)
        except Exception as e:
            logging.exception(f"Error during password verification: {e}")
            return False
