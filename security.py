from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import hashlib

class SecurityManager:
    def __init__(self):
        self.backend = default_backend()
        self.salt = os.urandom(16)
        
    def generate_key(self):
        """Generate a random AES key"""
        return os.urandom(32)  # 256 bits for AES-256
        
    def generate_iv(self):
        """Generate a random initialization vector"""
        return os.urandom(16)  # 128 bits for AES block size
        
    def encrypt_file(self, file_path):
        """Encrypt a file using AES-256-CBC"""
        # Generate key and IV
        key = self.generate_key()
        iv = self.generate_iv()
        
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Calculate SHA-256 hash
        file_hash = hashlib.sha256(data).digest()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad data to be multiple of 16 bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine hash and encrypted data
        final_data = file_hash + encrypted_data
        
        return final_data, key, iv
        
    def decrypt_file(self, encrypted_data, key, iv):
        """Decrypt a file using AES-256-CBC"""
        # Extract hash and encrypted data
        file_hash = encrypted_data[:32]  # SHA-256 is 32 bytes
        encrypted_content = encrypted_data[32:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # Unpad data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Verify hash
        calculated_hash = hashlib.sha256(data).digest()
        if calculated_hash != file_hash:
            raise ValueError("File integrity check failed - hash mismatch")
            
        return data
        
    def verify_integrity(self, data, expected_hash):
        """Verify the integrity of data using SHA-256"""
        calculated_hash = hashlib.sha256(data).digest()
        return calculated_hash == expected_hash 