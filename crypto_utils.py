import os
from cryptography.fernet import Fernet

def get_cipher():
    key = os.getenv("FERNET_KEY").encode()
    return Fernet(key)

def encrypt_password(password):
    return get_cipher().encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    try:
        return get_cipher().decrypt(encrypted_password.encode()).decode()
    except Exception:
        return None