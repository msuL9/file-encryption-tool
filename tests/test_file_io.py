import pytest
import os
from encryptor.file_io import encrypt_file, decrypt_file

def test_encrypt_decrypt_file(tmp_path):
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "encrypted.enc"
    decrypted_file = tmp_path / "decrypted.txt"

    with open(input_file, 'wb') as f:
        f.write(b"test content")

    encrypt_file(str(input_file), str(encrypted_file), "password")
    assert os.path.exists(encrypted_file)

    decrypt_file(str(encrypted_file), str(decrypted_file), "password")
    assert os.path.exists(decrypted_file)

    with open(decrypted_file, 'rb') as f:
        assert f.read() == b"test content"

    with pytest.raises(ValueError):
        decrypt_file(str(encrypted_file), str(decrypted_file), "wrongpass")