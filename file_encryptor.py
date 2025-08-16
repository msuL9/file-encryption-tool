import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(1024 * 1024):
            padded_chunk = chunk + b'\0' * (16 - len(chunk) % 16) if len(chunk) % 16 != 0 else chunk
            f_out.write(encryptor.update(padded_chunk))
        f_out.write(encryptor.finalize())
    print(f"File encrypted: {output_file}")

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(16)
        iv = f_in.read(16)
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        with open(output_file, 'wb') as f_out:
            while chunk := f_in.read(1024 * 1024):
                decrypted = decryptor.update(chunk)
                f_out.write(decrypted)
            f_out.write(decryptor.finalize().rstrip(b'\0'))
    print(f"File decrypted: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python file_encryptor.py [encrypt/decrypt] input_file output_file")
        sys.exit(1)
    
    mode, input_file, output_file = sys.argv[1:4]
    password = input("Enter password: ")
    
    if mode == "encrypt":
        encrypt_file(input_file, output_file, password)
    elif mode == "decrypt":
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")