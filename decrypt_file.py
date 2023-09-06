from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

private_key_file_path = "private_key.pem"
encrypted_data_file_path = "encrypted_data.bin"

try:
    with open(private_key_file_path, "rb") as private_key_file:
        private_key_pem = private_key_file.read()

    # Deserialize the private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None  # If the private key is not password-protected
    )

    with open(encrypted_data_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.PKCS1v15()
    )

    print("Decrypted Message:")
    print(decrypted_data.decode("utf-8"))  # Assuming the data is in UTF-8 encoding

except FileNotFoundError:
    print(f"Private key file '{private_key_file_path}' or encrypted data file '{encrypted_data_file_path}' not found.")
except ValueError as ve:
    print(f"Error loading private key: {ve}")
except Exception as e:
    print(f"Error decrypting data: {e}")
