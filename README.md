# Encryption Script

A simple tool for encrypting and decrypting text using multiple layers of security (OpenSSL, ZIP encryption, and Base64 encoding).

## Requirements

- Python 3.x
- OpenSSL command line tool
- Required Python packages: `pip install -r requirements.txt`

### Example

```bash
echo "Your secret text" | python encrypt.py -o encrypted_file.txt --password "test_password" --zip-password "zip_test"
```

### Decryption

```bash
python decrypt.py -d encrypted_file.txt --password "test_password" --zip-password "zip_test"
```
