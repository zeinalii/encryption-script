#!/bin/bash
# create a sample file
echo ">>> THIS IS A TEST MESSAGE <<<" > samples/sample_secret.txt

# Display the original content
echo "Original content:"
cat samples/sample_secret.txt
echo

# Encrypt the file
echo "Encrypting file..."
python encrypt.py -o samples/sample_encrypted.txt --password "test_password" --zip-password "zip_test" < samples/sample_secret.txt

# Show the encrypted content (Base64)
echo "Encrypted content (Base64):"
cat samples/sample_encrypted.txt | head -c 60
echo "..."
echo

# Decrypt the file
echo "Decrypting file..."
python decrypt.py -d samples/sample_encrypted.txt -o samples/sample_decrypted.txt --password "test_password" --zip-password "zip_test"

# Verify the contents match
echo "Decrypted content:"
cat samples/sample_decrypted.txt
echo

# Compare the original and decrypted files
echo "Verifying files match..."
if cmp -s samples/sample_secret.txt samples/sample_decrypted.txt; then
    echo "Success! The decrypted file matches the original."
else
    echo "Error: The decrypted file does not match the original."
fi



