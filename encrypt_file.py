from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Generate an RSA key pair (public and private key)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Extract the public key from the key pair
public_key = private_key.public_key()

# Serialize the public key to PEM format and save it to a file
with open("public_key.pem", "wb") as public_key_file:
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_file.write(public_key_pem)

# Data to be encrypted
data_to_encrypt = b"Hello, this is a secret message!"

# Encrypt the data using the public key with PKCS#1 v1.5 padding
encrypted_data = public_key.encrypt(
    data_to_encrypt,
    padding.PKCS1v15()
)

# Save the encrypted data to a file
with open("encrypted_data.bin", "wb") as encrypted_file:
    encrypted_file.write(encrypted_data)

print("Data encrypted and saved to 'encrypted_data.bin'")
