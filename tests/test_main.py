import pytest
from unittest.mock import patch
import sys
import subprocess
import os
from main import main

def test_main_encrypt(capsys, tmp_path):
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.enc"
    with open(input_file, 'w') as f:
        f.write("test")

    with patch.object(sys, 'argv', ['main.py', 'encrypt', str(input_file), str(output_file), 'pass']):
        main()
    captured = capsys.readouterr()
    assert "File encrypted" in captured.out

def test_main_decrypt_success(capsys, tmp_path):
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "encrypted.enc"
    decrypted_file = tmp_path / "decrypted.txt"

    with open(input_file, 'w') as f:
        f.write("test content")

    # Encrypt first
    with patch.object(sys, 'argv', ['main.py', 'encrypt', str(input_file), str(encrypted_file), 'password']):
        main()

    # Decrypt
    with patch.object(sys, 'argv', ['main.py', 'decrypt', str(encrypted_file), str(decrypted_file), 'password']):
        main()

    captured = capsys.readouterr()
    assert "File decrypted" in captured.out

    # Verify decrypted file
    with open(decrypted_file, 'r') as f:
        assert f.read() == "test content"

def test_main_decrypt_failure(tmp_path):
    encrypted_file = tmp_path / "encrypted.enc"
    decrypted_file = tmp_path / "decrypted.txt"

    with open(encrypted_file, 'wb') as f:
        f.write(b"dummy")  # Invalid data

    with patch.object(sys, 'argv', ['main.py', 'decrypt', str(encrypted_file), str(decrypted_file), 'password']):
        with pytest.raises(Exception):  # Expect failure
            main()

def test_script_execution(tmp_path):
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.enc"
    with open(input_file, 'w') as f:
        f.write("test")

    # Run script via subprocess with coverage to cover if __name__ == "__main__"
    result = subprocess.run(['python', '-m', 'coverage', 'run', '--parallel-mode', 'main.py', 'encrypt', str(input_file), str(output_file), 'pass'],
                            capture_output=True, text=True, cwd=os.getcwd())
    assert result.returncode == 0
    assert "File encrypted" in result.stdout