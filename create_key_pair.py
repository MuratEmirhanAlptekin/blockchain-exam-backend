from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Extract the public key
public_key = private_key.public_key()

# Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert the PEM format bytes to strings
private_key_pem_str = private_key_pem.decode('utf-8')
public_key_pem_str = public_key_pem.decode('utf-8')

# Print or use private_key_pem_str and public_key_pem_str as needed
print("Private Key:\n", private_key_pem_str)
print("Public Key:\n", public_key_pem_str)
