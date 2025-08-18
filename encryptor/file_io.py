import os
from .key import derive_key
from .crypto import encrypt, decrypt

def encrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, 'rb') as f:
        data = f.read()
    key, salt = derive_key(password)
    ciphertext, iv, mac = encrypt(data, key)
    with open(output_path, 'wb') as f:
        f.write(salt + iv + mac + ciphertext)

def decrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, 'rb') as f:
        data = f.read()
    salt = data[:16]
    iv = data[16:32]
    mac = data[32:64]
    ciphertext = data[64:]
    key, _ = derive_key(password, salt)
    plaintext = decrypt(ciphertext, key, iv, mac)
    with open(output_path, 'wb') as f:
        f.write(plaintext)