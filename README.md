# file-encryption-tool

![Demo](demo.gif)

A secure file encryption tool using AES-256 and PBKDF2 in Python.

## Usage
- Encrypt: `python file_encryptor.py encrypt input.txt output.enc`
- Decrypt: `python file_encryptor.py decrypt output.enc decrypted.txt`

Enter password when prompted.

## Contributions
- Implemented core encryption/decryption logic.
- Added key derivation for security.
