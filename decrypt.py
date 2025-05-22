#!/usr/bin/env python3
import os
import base64
import getpass
import subprocess
import tempfile
import zipfile
import signal
import sys
import atexit
import argparse

# Global tracking of temporary files for cleanup
_temp_files = set()
_temp_dirs = set()


def deformat_encrypted_data(encrypted_data):
    return encrypted_data.split("------ text ----\n")[1].split("------ end of text ----")[0]


def register_temp_file(filepath):
    """Register a temporary file for cleanup"""
    _temp_files.add(filepath)

def register_temp_dir(dirpath):
    """Register a temporary directory for cleanup"""
    _temp_dirs.add(dirpath)

def cleanup_temp_files():
    """Clean up all registered temporary files and directories"""
    for filepath in _temp_files:
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except Exception:
            pass
    
    for dirpath in _temp_dirs:
        try:
            if os.path.exists(dirpath):
                os.rmdir(dirpath)
        except Exception:
            pass

def signal_handler():
    """Handle signals like CTRL+C by cleaning up before exit"""
    print("\nInterrupted. Cleaning up temporary files...", file=sys.stderr)
    cleanup_temp_files()
    sys.exit(1)

# Set up cleanup handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup_temp_files)

def is_running_tests():
    """Check if we're running under pytest"""
    return any(arg in sys.argv for arg in ['-s', '--collect-only', 'pytest', '-v', 'test_'])

def get_output_path(filename):
    """Get an absolute output path in the current working directory"""
    # Get the actual current working directory
    current_dir = os.getcwd()
    
    # Create absolute path to the output file in the current directory
    return os.path.abspath(os.path.join(current_dir, filename))

def parse_arguments():
    """Parse command-line arguments"""
    # When running under pytest, return a default namespace to avoid argument conflicts
    if is_running_tests():
        args = argparse.Namespace()
        args.decrypt = None
        args.output = None  # Will default to cwd
        args.salt = None
        args.zip_password = None
        args.password = None
        return args
        
    parser = argparse.ArgumentParser(description="Decrypt a multi-layer encrypted file")
    parser.add_argument("-d", "--decrypt", metavar="FILE", 
                        help="Decrypt specified file and print content to stdout")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output filename for decrypted content (default: decrypted_secret.txt in current directory)")
    parser.add_argument("-s", "--salt", 
                        help="Fixed salt for OpenSSL decryption (hex value, e.g., 1234567890ABCDEF)")
    parser.add_argument("-p", "--password", 
                        help="Password for OpenSSL decryption")
    parser.add_argument("-z", "--zip-password", 
                        help="Password for ZIP extraction")
    return parser.parse_args()

def base64_decode(encoded_data):
    """Decode Base64 data to binary"""
    return base64.b64decode(encoded_data)

def extract_from_zip(zip_data, password):
    """Extract content from a password-protected zip file"""
    temp_dir = tempfile.mkdtemp()
    register_temp_dir(temp_dir)
    
    zip_file_path = os.path.join(temp_dir, "secret.zip")
    register_temp_file(zip_file_path)
    
    extracted_file_path = os.path.join(temp_dir, "secret.openssl")
    register_temp_file(extracted_file_path)
    
    try:
        # Write zip data to temporary file
        with open(zip_file_path, "wb") as f:
            f.write(zip_data)
        
        # Extract from the zip file
        with zipfile.ZipFile(zip_file_path, "r") as zip_file:
            # Set the password for extraction
            zip_file.setpassword(password.encode())
            # Extract to the temporary directory
            zip_file.extractall(path=temp_dir)
        
        # Read the extracted file
        with open(extracted_file_path, "rb") as f:
            extracted_data = f.read()
        
        return extracted_data
    finally:
        # Cleanup is handled by the atexit handler
        pass

def decrypt_with_openssl(encrypted_data, password, fixed_salt=None):
    """Decrypt data using OpenSSL AES-256-CBC
    
    Args:
        encrypted_data: Data to decrypt
        password: Password for decryption
        fixed_salt: If provided, use this hex-encoded salt instead of the default
    """
    temp_input = tempfile.NamedTemporaryFile(delete=False)
    temp_input_path = temp_input.name
    register_temp_file(temp_input_path)
    
    temp_output_path = temp_input_path + ".dec"
    register_temp_file(temp_output_path)
    
    try:
        # Write encrypted data to temporary file
        temp_input.write(encrypted_data)
        temp_input.close()
        
        # Use OpenSSL for decryption
        cmd = [
            "openssl", "enc", "-aes-256-cbc", "-d",
            "-pbkdf2",
            "-in", temp_input_path,
            "-out", temp_output_path,
            "-pass", f"pass:{password}"
        ]
        
        # Add salt parameter if specified
        if fixed_salt:
            cmd.extend(["-S", fixed_salt])
        else:
            cmd.append("-salt")
        
        subprocess.run(cmd, check=True)
        
        # Read decrypted data
        with open(temp_output_path, "r") as f:
            decrypted_data = f.read()
        
        return decrypted_data
    
    except subprocess.CalledProcessError:
        raise ValueError("Decryption failed. Incorrect password or corrupted data.")
    finally:
        # Cleanup is handled by the atexit handler
        pass

def decrypt_file(filename, save_to_file=True, fixed_salt=None, openssl_pass=None, zip_pass=None):
    """Decrypt a file and return its contents"""
    try:
        # Read the encrypted Base64 data
        with open(filename, "r") as f:
            encoded_data = deformat_encrypted_data(f.read())
        
        # Step 1: Base64 decode
        if save_to_file:
            print("Decoding from Base64...")
        zip_data = base64_decode(encoded_data)
        
        # Get ZIP password - either from argument or prompt
        if zip_pass is None:
            zip_pass = getpass.getpass("Enter ZIP password: ")
        
        # Step 2: Extract from password-protected ZIP
        if save_to_file:
            print("Extracting from password-protected ZIP...")
        encrypted_data = extract_from_zip(zip_data, zip_pass)
        
        # Get OpenSSL password - either from argument or prompt
        if openssl_pass is None:
            openssl_pass = getpass.getpass("Enter OpenSSL decryption password: ")
        
        # Step 3: Decrypt with OpenSSL
        if save_to_file:
            print("Decrypting with OpenSSL AES-256-CBC...")
        plaintext = decrypt_with_openssl(encrypted_data, openssl_pass, fixed_salt)
        
        # Return the decrypted content
        return plaintext
        
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    try:
        args = parse_arguments()
        
        # Get fixed salt if provided
        fixed_salt = None
        if hasattr(args, 'salt') and args.salt:
            fixed_salt = args.salt
        
        # Get passwords if provided
        openssl_pass = args.password if hasattr(args, 'password') else None
        zip_pass = args.zip_password if hasattr(args, 'zip_password') else None
        
        # Direct decryption mode with -d flag
        if hasattr(args, 'decrypt') and args.decrypt:
            input_file = args.decrypt
        else:
            # Interactive mode
            input_file = input("Enter the path to the encrypted file (default: encrypted_secret.txt in current directory): ").strip()
            if not input_file:
                # Default to encrypted_secret.txt in the current working directory
                input_file = get_output_path("encrypted_secret.txt")
            
        plaintext = decrypt_file(args.decrypt, save_to_file=False, fixed_salt=fixed_salt,
                        openssl_pass=openssl_pass, zip_pass=zip_pass)
        if not (hasattr(args, 'output') and args.output):
            print(f"{plaintext}")
            
        else:
            output_file = args.output
            with open(output_file, "w") as f:
                f.write(plaintext)
        
            print(f"\nDecryption complete! Output saved to {output_file}")
        
    finally:
        # Make sure we clean up on exit
        cleanup_temp_files()

if __name__ == "__main__":
    main()
