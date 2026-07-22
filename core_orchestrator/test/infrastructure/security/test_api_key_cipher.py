import pytest
from core_orchestrator.infrastructure.security.api_key_cipher import ApiKeyCipher


def test_api_key_cipher_encrypt_decrypt():
    key = ApiKeyCipher.generate_key()
    cipher = ApiKeyCipher(key)

    original_api_key = "gsk_test_1234567890abcdefghijklmn"
    encrypted = cipher.encrypt(original_api_key)

    assert encrypted != original_api_key
    assert isinstance(encrypted, str)

    decrypted = cipher.decrypt(encrypted)
    assert decrypted == original_api_key


def test_api_key_cipher_empty_strings():
    key = ApiKeyCipher.generate_key()
    cipher = ApiKeyCipher(key)

    assert cipher.encrypt("") == ""
    assert cipher.decrypt("") == ""
