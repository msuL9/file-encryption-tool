import pytest
from cryptography.exceptions import InvalidSignature
from encryptor.crypto import encrypt, decrypt

def test_encrypt_decrypt():
    key = b'\x00' * 32
    data = b"test data"
    ciphertext, iv, mac = encrypt(data, key)
    assert len(iv) == 16
    assert len(mac) == 32

    decrypted = decrypt(ciphertext, key, iv, mac)
    assert decrypted == data

    with pytest.raises(InvalidSignature):
        decrypt(ciphertext + b'\x00', key, iv, mac)