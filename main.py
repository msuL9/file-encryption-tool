import argparse
from encryptor.file_io import encrypt_file, decrypt_file

def main():
    parser = argparse.ArgumentParser(description="Simple File Encryptor")
    subparsers = parser.add_subparsers(dest='command', required=True)

    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('input', help="Input file path")
    encrypt_parser.add_argument('output', help="Output file path")
    encrypt_parser.add_argument('password', help="Password")

    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('input', help="Input file path")
    decrypt_parser.add_argument('output', help="Output file path")
    decrypt_parser.add_argument('password', help="Password")

    args = parser.parse_args()

    if args.command == 'encrypt':
        encrypt_file(args.input, args.output, args.password)
        print(f"File encrypted: {args.output}")
    elif args.command == 'decrypt':
        decrypt_file(args.input, args.output, args.password)
        print(f"File decrypted: {args.output}")

if __name__ == "__main__":
    main()