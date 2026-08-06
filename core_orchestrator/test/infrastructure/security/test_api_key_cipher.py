from core_orchestrator.infrastructure.adapters.security.api_key_cipher_adapter import ApiKeyCipherAdapter


def test_api_key_cipher_encrypt_decrypt():
    key = ApiKeyCipherAdapter.generate_key()
    cipher = ApiKeyCipherAdapter(key)

    original_api_key = "gsk_test_1234567890abcdefghijklmn"
    encrypted = cipher.encrypt(original_api_key)

    assert encrypted != original_api_key
    assert isinstance(encrypted, str)

    decrypted = cipher.decrypt(encrypted)
    assert decrypted == original_api_key


def test_api_key_cipher_empty_strings():
    key = ApiKeyCipherAdapter.generate_key()
    cipher = ApiKeyCipherAdapter(key)

    assert cipher.encrypt("") == ""
    assert cipher.decrypt("") == ""
