import pytest
import sys
import subprocess
import tempfile
from pathlib import Path

# Ensure the root directory is in the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import functions from encrypt.py and decrypt.py
from encrypt import encrypt_with_openssl, create_password_protected_zip, base64_encode
from decrypt import base64_decode, extract_from_zip, decrypt_with_openssl

@pytest.mark.parametrize(
    "secret, expected_encrypted, openssl_pass, zip_pass, salt",
    [
        (
            "secret number 1", 
            "UEsDBBQAAAAIAAAAIVYSNArBEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zjdVV5VKv0+0k98+3JDFv67wIAUEsBAhQDFAAAAAgAAAAhVhI0CsETAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password1", 
            "zip_password1",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 2", 
            "UEsDBBQAAAAIAAAAIVZcSJF7EwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zbpznTc8dHU6tPha3Mi1Y5PAEAUEsBAhQDFAAAAAgAAAAhVlxIkXsTAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password2", 
            "zip_password2",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 3", 
            "UEsDBBQAAAAIAAAAIVbU8h0JEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2yb5FPZZ10v8f7PKpfpfvvr1wEAUEsBAhQDFAAAAAgAAAAhVtTyHQkTAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password3", 
            "zip_password3",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 4", 
            "UEsDBBQAAAAIAAAAIVaVsemwEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zbbawWc9DKfevOTRMqPXctYwIAUEsBAhQDFAAAAAgAAAAhVpWx6bATAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password4", 
            "zip_password4",
            "AABBCCDDEEFF0011"
         ),
    ],
)
def test_encryption(secret, expected_encrypted, openssl_pass, zip_pass, salt):
    """Test that encrypting a secret results in the expected encrypted value."""
    from encrypt import format_encrypted_data
    expected_encrypted = format_encrypted_data(expected_encrypted)
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        encrypted_file = temp_dir / "encrypted.txt"
        subprocess.run(["python", "encrypt.py", "-o", encrypted_file, "--password", openssl_pass, "--zip-password", zip_pass, "--salt", salt, secret])
        assert encrypted_file.exists()
        with open(encrypted_file, "r") as f:
            encrypted_data = f.read()
        assert encrypted_data == expected_encrypted

        # run the same thing using piped input
        result = subprocess.run(["python", "encrypt.py", "-o", encrypted_file, "--password", openssl_pass, "--zip-password", zip_pass, "--salt", salt], input=secret, capture_output=True, text=True)
        assert result.returncode == 0
        with open(encrypted_file, "r") as f:
            encrypted_data = f.read()
        assert encrypted_data == expected_encrypted

@pytest.mark.parametrize(
    "expected_secret, encrypted, openssl_pass, zip_pass, salt",
    [
        (
            "secret number 1", 
            "UEsDBBQAAAAIAAAAIVYSNArBEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zjdVV5VKv0+0k98+3JDFv67wIAUEsBAhQDFAAAAAgAAAAhVhI0CsETAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password1", 
            "zip_password1",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 2", 
            "UEsDBBQAAAAIAAAAIVZcSJF7EwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zbpznTc8dHU6tPha3Mi1Y5PAEAUEsBAhQDFAAAAAgAAAAhVlxIkXsTAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password2", 
            "zip_password2",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 3", 
            "UEsDBBQAAAAIAAAAIVbU8h0JEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2yb5FPZZ10v8f7PKpfpfvvr1wEAUEsBAhQDFAAAAAgAAAAhVtTyHQkTAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password3", 
            "zip_password3",
            "AABBCCDDEEFF0011"
         ),
        (
            "secret number 4", 
            "UEsDBBQAAAAIAAAAIVaVsemwEwAAABAAAAAOAAAAc2VjcmV0Lm9wZW5zc2zbbawWc9DKfevOTRMqPXctYwIAUEsBAhQDFAAAAAgAAAAhVpWx6bATAAAAEAAAAA4AAAAAAAAAAAAAAIABAAAAAHNlY3JldC5vcGVuc3NsUEsFBgAAAAABAAEAPAAAAD8AAAAAAA==",
            "openssl_password4", 
            "zip_password4",
            "AABBCCDDEEFF0011"
         ),
    ],
)
def test_decryption(expected_secret, encrypted, openssl_pass, zip_pass, salt):
    from encrypt import format_encrypted_data
    encrypted = format_encrypted_data(encrypted)
    """Test that decrypting an encrypted value results in the expected secret."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        encrypted_file = temp_dir / "encrypted.txt"
        
        # Write the encrypted data to a file
        with open(encrypted_file, "w") as f:
            f.write(encrypted)
        
        # Test command-line decryption with password arguments
        result = subprocess.run([
            "python", "decrypt.py", 
            "-d", str(encrypted_file),
            "--salt", salt,
            "--password", openssl_pass,
            "--zip-password", zip_pass
        ], text=True, capture_output=True)
        
        assert result.returncode == 0, f"Decryption failed with error: {result.stderr}"
        
        # The decrypted content should be in stdout
        decrypted_content = result.stdout.strip()
        assert decrypted_content == expected_secret
        
        
        result_encrypted_file = temp_dir / "result_encrypted.txt"
        result = subprocess.run([
            "python", "decrypt.py", 
            "-d", str(encrypted_file),
            "-o", str(result_encrypted_file),
            "--salt", salt,
            "--password", openssl_pass,
            "--zip-password", zip_pass
        ], text=True, capture_output=True)
        with open(result_encrypted_file, "r") as f:
            decrypted_content = f.read()
        assert decrypted_content == expected_secret