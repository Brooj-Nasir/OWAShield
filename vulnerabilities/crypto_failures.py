from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib

# Insecure Configuration
# INSECURE_KEY = b'weakpassword123' * 3  # 32 bytes for AES256
INSECURE_KEY = b"c8079558a0da4fc3c3f564717b769e98"

# Secure Configuration
SECRET_PEPPER = os.urandom(32)  # Should be stored securely in real apps

def insecure_encrypt(data):
    """Insecure AES-256 ECB with static key"""
    cipher = Cipher(
        algorithms.AES(INSECURE_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Bad padding practice
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    return encryptor.update(padded_data) + encryptor.finalize()

def secure_encrypt(data):
    """Secure AES-256 GCM with proper key derivation"""
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # Key derivation
    key = hashlib.pbkdf2_hmac(
        'sha256',
        SECRET_PEPPER + data.encode(),
        salt,
        600000,
        32
    )
    
    # Encryption
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Authenticated encryption
    ct = encryptor.update(data.encode()) + encryptor.finalize()
    
    return (salt, iv, ct, encryptor.tag)