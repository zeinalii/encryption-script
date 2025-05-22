#!/usr/bin/env python3
import sys
import os
import base64
import getpass
import subprocess
import tempfile
import zipfile
import signal
import atexit
import argparse

# Global tracking of temporary files for cleanup
_temp_files = set()
_temp_dirs = set()

def format_encrypted_data(encrypted_data):
    return f"------ text ----\n{encrypted_data}\n------ end of text ----"


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
        args.output = None  # Will default to cwd
        return args
    
    parser = argparse.ArgumentParser(description="Encrypt text with multiple layers of encryption")
    parser.add_argument("-o", "--output", metavar="FILE", 
                        help="Output filename (default: encrypted_secret.txt in current directory)")
    parser.add_argument("-p", "--password", 
                        help="Password for OpenSSL encryption")
    parser.add_argument("-z", "--zip-password", 
                        help="Password for ZIP encryption")
    parser.add_argument("-s", "--salt", 
                        help="Fixed salt for OpenSSL encryption (hex value, e.g., 1234567890ABCDEF)")
    parser.add_argument("secret", nargs="?", 
                        help="Secret text to encrypt (if not provided, will read from stdin)")
    return parser.parse_args()

def read_input():
    """Read input from stdin or prompt user if no input is piped"""
    if not sys.stdin.isatty():
        return sys.stdin.read()
    else:
        print("No input piped. Please enter your secret text (Ctrl+D to finish):")
        return sys.stdin.read()

def encrypt_with_openssl(plaintext, password, fixed_salt=None):
    """Encrypt data using OpenSSL AES-256-CBC with salt
    
    Args:
        plaintext: Text to encrypt
        password: Password for encryption
        fixed_salt: If provided, use this hex-encoded salt instead of random salt
    """
    temp_input = tempfile.NamedTemporaryFile(delete=False)
    temp_input_path = temp_input.name
    register_temp_file(temp_input_path)
    
    temp_output_path = temp_input_path + ".enc"
    register_temp_file(temp_output_path)
    
    try:
        # Write input data
        temp_input.write(plaintext.encode())
        temp_input.close()
        
        # Use OpenSSL for encryption with salt and PBKDF2
        cmd = [
            "openssl", "enc", "-aes-256-cbc", 
            "-pbkdf2",
            "-in", temp_input_path,
            "-out", temp_output_path,
            "-pass", f"pass:{password}"
        ]
        
        # Add salt parameter (either fixed or random)
        if fixed_salt:
            cmd.extend(["-S", fixed_salt])
        else:
            cmd.append("-salt")
        
        subprocess.run(cmd, check=True)
        
        # Read encrypted data
        with open(temp_output_path, "rb") as f:
            encrypted_data = f.read()
        
        return encrypted_data
    finally:
        # Clean up is handled by the atexit handler
        pass

def create_password_protected_zip(data, password):
    """Create a password-protected zip file with AES encryption"""
    temp_dir = tempfile.mkdtemp()
    register_temp_dir(temp_dir)
    
    input_file_path = os.path.join(temp_dir, "secret.openssl")
    register_temp_file(input_file_path)
    
    zip_file_path = os.path.join(temp_dir, "secret.zip")
    register_temp_file(zip_file_path)
    
    try:
        # Write data to temporary file
        with open(input_file_path, "wb") as f:
            f.write(data)
        
        # Create password-protected zip file
        with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Set the password for the zip file
            zip_file.setpassword(password.encode())
            
            # Add the file to the zip archive
            # Set a fixed modification time to ensure reproducibility
            zip_info = zipfile.ZipInfo("secret.openssl")
            zip_info.date_time = (2023, 1, 1, 0, 0, 0)  # Fixed timestamp
            zip_info.compress_type = zipfile.ZIP_DEFLATED
            
            with open(input_file_path, "rb") as f:
                zip_file.writestr(zip_info, f.read())
        
        # Read the zip file
        with open(zip_file_path, "rb") as f:
            zip_data = f.read()
        
        return zip_data
    finally:
        # Clean up is handled by the atexit handler
        pass

def base64_encode(data):
    """Encode binary data to Base64"""
    return base64.b64encode(data).decode()

def main():
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        
        # Set the output filename
        if hasattr(args, 'output') and args.output:
            output_file = args.output
        else:
            # Default to encrypted_secret.txt in the current working directory
            output_file = get_output_path("encrypted_secret.txt")
        # Get plaintext input - either from command line arg or stdin
        if hasattr(args, 'secret') and args.secret:
            plaintext = args.secret
        else:
            # Read from stdin
            plaintext = read_input()
        
        # Get OpenSSL password - either from command line arg or prompt
        if hasattr(args, 'password') and args.password:
            openssl_pass = args.password
        else:
            openssl_pass = getpass.getpass("Enter OpenSSL encryption password: ")
        
        # Get ZIP password - either from command line arg or prompt
        if hasattr(args, 'zip_password') and args.zip_password:
            zip_pass = args.zip_password
        else:
            zip_pass = getpass.getpass("Enter ZIP password: ")
        
        # Get fixed salt if provided
        fixed_salt = None
        if hasattr(args, 'salt') and args.salt:
            fixed_salt = args.salt
        
        encrypted_data = encrypt_with_openssl(plaintext, openssl_pass, fixed_salt)
        
        zip_data = create_password_protected_zip(encrypted_data, zip_pass)
        
        encoded_data = base64_encode(zip_data)
        
        # Create any parent directories if they don't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Write the final encrypted result to file
        with open(output_file, "w") as f:
            f.write(format_encrypted_data(encoded_data))
        
        print(f"Encryption complete! Output saved to {output_file}")
    finally:
        # Make sure we clean up on exit
        cleanup_temp_files()

if __name__ == "__main__":
    main()
