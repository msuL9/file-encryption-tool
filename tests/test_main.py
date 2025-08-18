import pytest
from unittest.mock import patch
import sys
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

def test_main_decrypt(capsys, tmp_path):
    input_file = tmp_path / "input.enc"
    output_file = tmp_path / "output.txt"
    with open(input_file, 'wb') as f:
        f.write(b"dummy")  # Mock encrypted file

    with patch.object(sys, 'argv', ['main.py', 'decrypt', str(input_file), str(output_file), 'pass']):
        with pytest.raises(Exception):  # Expect failure on mock data
            main()