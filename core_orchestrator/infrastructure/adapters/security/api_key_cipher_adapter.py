from cryptography.fernet import Fernet

from core_orchestrator.domain.exceptions.auth_exceptions import InvalidTokenError
from core_orchestrator.domain.ports.auth.api_key_cipher_port import ApiKeyCipherPort


class ApiKeyCipherAdapter(ApiKeyCipherPort):
    """
    Provides encryption and decryption functionalities for API keys using the Fernet cipher.

    This class allows for securely encrypting confidential API keys into a base64-encoded ciphertext
    and decrypting them back into their plaintext form. It uses the encryption key provided during
    initialization and includes a method to generate new encryption keys when required.
    """

    def __init__(self, encryption_key: str):
        """
        Initializes a new instance of the class responsible for encryption
        operations using the provided encryption key.

        Parameters:
        encryption_key (str): Encryption key to initialize the encryption mechanism.
            The encryption key must be a non-empty string.

        Raises:
        InvalidTokenError: If the provided encryption key is empty.
        """
        if not encryption_key:
            raise InvalidTokenError("Encryption key must not be empty.")

        self._fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using a Fernet symmetric encryption mechanism.

        The method takes a plaintext string as input and returns an encrypted string
        encoded in UTF-8. The encryption is performed using an internal Fernet
        instance. If the plaintext is empty or None, the method returns an empty
        string without performing encryption.

        Parameters:
            plaintext (str): The plaintext string to be encrypted.

        Returns:
            str: The encrypted string in UTF-8 format.
        """
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts an encrypted string using the Fernet symmetric encryption scheme. This
        method is designed to take in an encrypted string, decode it, and return the
        original plaintext. The decryption process ensures data integrity by verifying
        that the ciphertext has not been tampered with.

        Args:
            ciphertext (str): The encrypted string to be decrypted, encoded in UTF-8.

        Returns:
            str: The original plaintext string after decryption. Returns an empty
            string if the given ciphertext is empty.
        """
        if not ciphertext:
            return ""
        return self._fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')

    @staticmethod
    def generate_key() -> str:
        """
        Generates a new encryption key as a string.

        This static method utilizes the `Fernet` library to generate a secure encryption
        key that can be used for cryptographic operations. The key is returned as a UTF-8
        encoded string.

        @return: A newly generated encryption key as a string.
        @rtype: str
        """
        return Fernet.generate_key().decode('utf-8')
