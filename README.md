# file-encryption-tool

![Demo](demo.gif)

A secure AES-256 file encryption/decryption tool using Python and cryptography library.

## Features
- Encrypt/decrypt files with password-derived keys (PBKDF2).
- Handles large files in chunks.

## Installation
1. Install dependencies: `pip install -r requirements.txt`

## Usage
1. Encrypt: `python file_encryptor.py encrypt input.txt output.enc` (enter password).
2. Decrypt: `python file_encryptor.py decrypt output.enc decrypted.txt` (enter password).

## Contributions
- Implemented AES-256 CBC mode encryption.
- Added secure key derivation and padding.
