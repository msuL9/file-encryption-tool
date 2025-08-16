import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import sys  # Added for flush

def derive_key(password: str, salt: bytes) -> bytes:
    print("Debug: Deriving key...")
    sys.stdout.flush()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    print("Debug: Key derived.")
    sys.stdout.flush()
    return key

def encrypt_file(input_file: str, output_file: str, password: str):
    print("Debug: Generating salt...")
    sys.stdout.flush()
    salt = os.urandom(16)
    print("Debug: Salt generated.")
    sys.stdout.flush()
    key = derive_key(password, salt)
    print("Debug: Generating IV...")
    sys.stdout.flush()
    iv = os.urandom(16)
    print("Debug: IV generated.")
    sys.stdout.flush()
    print("Debug: Creating cipher...")
    sys.stdout.flush()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    print("Debug: Cipher created.")
    sys.stdout.flush()
    encryptor = cipher.encryptor()
    print("Debug: Encryptor ready.")
    sys.stdout.flush()
    
    print("Debug: Opening files...")
    sys.stdout.flush()
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        print("Debug: Files opened.")
        sys.stdout.flush()
        print("Debug: Writing salt and IV...")
        sys.stdout.flush()
        f_out.write(salt + iv)
        print("Debug: Salt and IV written.")
        sys.stdout.flush()
        print("Debug: Starting encryption loop...")
        sys.stdout.flush()
        chunk_count = 0
        while chunk := f_in.read(1024 * 1024):
            chunk_count += 1
            print(f"Debug: Processing chunk {chunk_count} (size: {len(chunk)} bytes)...")
            sys.stdout.flush()
            padded_chunk = chunk + b'\0' * (16 - len(chunk) % 16) if len(chunk) % 16 != 0 else chunk
            f_out.write(encryptor.update(padded_chunk))
            print(f"Debug: Chunk {chunk_count} encrypted.")
            sys.stdout.flush()
        print("Debug: Encryption loop finished.")
        sys.stdout.flush()
        print("Debug: Finalizing encryption...")
        sys.stdout.flush()
        f_out.write(encryptor.finalize())
        print("Debug: Encryption finalized.")
        sys.stdout.flush()
    print(f"File encrypted: {output_file}")
    sys.stdout.flush()

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
    sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python file_encryptor.py [encrypt/decrypt] input_file output_file")
        sys.stdout.flush()
        sys.exit(1)
    
    mode, input_file, output_file = sys.argv[1:4]
    password = input("Enter password: ")
    print("Debug: Password entered, starting operation...")
    sys.stdout.flush()
    
    if mode == "encrypt":
        encrypt_file(input_file, output_file, password)
    elif mode == "decrypt":
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
        sys.stdout.flush()