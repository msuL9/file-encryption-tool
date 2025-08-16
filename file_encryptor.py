# Import necessary modules: os for file operations, cryptography for encryption tools, base64 (not used here but imported for potential future expansion).
import os
from cryptography.hazmat.primitives import hashes  # For hashing algorithms.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For key derivation.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption.
from cryptography.hazmat.backends import default_backend  # Default backend for crypto operations.
import base64  # Optional, for encoding if needed later.

# Function to derive a secure key from password and salt using PBKDF2.
# Step: This makes weak passwords stronger by hashing repeatedly.
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 hash.
        length=32,  # 256-bit key for AES-256.
        salt=salt,  # Random salt to prevent rainbow table attacks.
        iterations=100000,  # High iterations for security (slows brute-force).
        backend=default_backend()  # Use default crypto backend.
    )
    return kdf.derive(password.encode())  # Derive and return the key.

# Function to encrypt a file.
# Step: Generate salt and IV, encrypt chunks of the file, write to output.
def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)  # Generate 16-byte random salt.
    key = derive_key(password, salt)  # Derive key from password and salt.
    iv = os.urandom(16)  # Generate 16-byte random initialization vector for CBC mode.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Set up AES-CBC cipher.
    encryptor = cipher.encryptor()  # Create encryptor object.
    
    # Open input file for reading (binary), output for writing (binary).
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt + iv)  # Write salt and IV to output file (needed for decryption).
        while chunk := f_in.read(1024 * 1024):  # Read file in 1MB chunks to handle large files.
            # Pad chunk if not multiple of 16 bytes (AES block size).
            padded_chunk = chunk + b'\0' * (16 - len(chunk) % 16) if len(chunk) % 16 != 0 else chunk
            f_out.write(encryptor.update(padded_chunk))  # Encrypt and write chunk.
        f_out.write(encryptor.finalize())  # Finalize encryption (handles any remaining data).
    print(f"File encrypted: {output_file}")  # Print success message.

# Function to decrypt a file.
# Step: Read salt and IV from file, decrypt chunks, remove padding.
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f_in:  # Open encrypted file for reading.
        salt = f_in.read(16)  # Read stored salt.
        iv = f_in.read(16)  # Read stored IV.
        key = derive_key(password, salt)  # Derive key using same password and salt.
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Set up decryptor.
        decryptor = cipher.decryptor()  # Create decryptor object.
        
        with open(output_file, 'wb') as f_out:  # Open output for writing.
            while chunk := f_in.read(1024 * 1024):  # Read in 1MB chunks.
                decrypted = decryptor.update(chunk)  # Decrypt chunk.
                f_out.write(decrypted)  # Write decrypted data.
            # Finalize and remove padding (null bytes).
            f_out.write(decryptor.finalize().rstrip(b'\0'))
    print(f"File decrypted: {output_file}")  # Print success message.

# Main script entry point.
if __name__ == "__main__":
    import sys  # Import sys for command-line arguments.
    # Check if enough arguments are provided.
    if len(sys.argv) < 4:
        print("Usage: python file_encryptor.py [encrypt/decrypt] input_file output_file")
        sys.exit(1)  # Exit if invalid.
    
    mode, input_file, output_file = sys.argv[1:4]  # Parse arguments.
    password = input("Enter password: ")  # Prompt for password (hidden in some terminals).
    
    # Run encrypt or decrypt based on mode.
    if mode == "encrypt":
        encrypt_file(input_file, output_file, password)
    elif mode == "decrypt":
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")