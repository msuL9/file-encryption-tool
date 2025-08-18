# file-encryption-tool

## Overview
This project is a command-line tool for encrypting and decrypting files using AES-256 in CBC mode, with PBKDF2 for key derivation from a password. It includes HMAC for integrity verification and PKCS7 padding. Built with modularity (separate modules for key derivation, crypto operations, and file I/O), it uses the `cryptography` library. Includes unit tests with 100% coverage via `pytest` and `coverage`.

## Features
- Secure encryption/decryption with password-based key.
- Integrity checks to detect tampering.
- CLI interface for ease of use.

## Requirements
- Python 3.13.6
- Dependencies (from `requirements.txt`):
  ```
  cryptography==43.0.3
  pytest==8.3.3
  coverage==7.6.1
  ```

## Installation
1. Clone the repository:
   ```
   git clone <repo-url>
   cd file_encryptor
   ```
2. Create and activate virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
- Encrypt: `python main.py encrypt <input_file> <output_file> <password>`
- Decrypt: `python main.py decrypt <input_file> <output_file> <password>`

Example:
- Encrypt: `python main.py encrypt test.txt encrypted.enc mypassword`
- Decrypt: `python main.py decrypt encrypted.enc decrypted.txt mypassword`

## Testing
Run tests with 100% coverage:
```
coverage run --parallel-mode -m pytest tests/
coverage combine
coverage report -m
```

## Project Structure
- `encryptor/`: Core modules (`key.py`, `crypto.py`, `file_io.py`).
- `main.py`: CLI entry point.
- `tests/`: Unit tests.
- `.coveragerc`: Coverage config.

Deactivate venv: `deactivate`
