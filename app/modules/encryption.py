"""
Encryption module for SecureHide
Provides AES and RSA encryption functionality
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import tempfile


class AESCipher:
    """AES encryption for message content"""
    
    def __init__(self, password=None):
        """Initialize with a password or generate a random key"""
        if password:
            # Derive key from password
            salt = os.urandom(16)
            self.salt = salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            self.key = kdf.derive(password.encode())
        else:
            # Generate a random key
            self.key = os.urandom(32)  # 256 bits for AES-256
            self.salt = None
    
    def encrypt(self, plaintext):
        """Encrypt a message using AES-256-GCM"""
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(12)  # 96 bits for GCM mode
        
        # Create a cipher object
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        # Get an encryptor
        encryptor = cipher.encryptor()
        
        # Pad the plaintext to a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return the IV, tag, and ciphertext
        tag = encryptor.tag
        
        # Combine salt (if exists), IV, tag, and ciphertext
        result = {}
        if self.salt:
            result['salt'] = base64.b64encode(self.salt).decode()
        result['iv'] = base64.b64encode(iv).decode()
        result['tag'] = base64.b64encode(tag).decode()
        result['ciphertext'] = base64.b64encode(ciphertext).decode()
        
        return result
    
    def decrypt(self, encrypted_data, password=None):
        """Decrypt a message encrypted with AES-256-GCM"""
        # Extract the IV, tag, and ciphertext
        iv = base64.b64decode(encrypted_data['iv'])
        tag = base64.b64decode(encrypted_data['tag'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # If a password was provided and salt exists, derive the key
        if password and 'salt' in encrypted_data:
            salt = base64.b64decode(encrypted_data['salt'])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:
            key = self.key
        
        # Create a cipher object
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        
        # Get a decryptor
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext.decode()


class RSACipher:
    """RSA encryption for key exchange"""
    
    def __init__(self, key_size=2048):
        """Generate a new RSA key pair or load existing keys"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt(self, plaintext):
        """Encrypt a message using RSA"""
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    def decrypt(self, ciphertext):
        """Decrypt a message using RSA"""
        plaintext = self.private_key.decrypt(
            base64.b64decode(ciphertext),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def encrypt_aes_key(self, aes_key):
        """Encrypt an AES key using RSA"""
        encrypted_key = self.public_key.encrypt(
            aes_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode()
    
    def decrypt_aes_key(self, encrypted_key):
        """Decrypt an AES key using RSA"""
        aes_key = self.private_key.decrypt(
            base64.b64decode(encrypted_key),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key


def serialize_private_key(private_key):
    """Convert an RSA private key object to a serializable format (PEM string)"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(pem).decode('utf-8')


def deserialize_private_key(pem_b64):
    """Convert a serialized private key back to an RSA private key object"""
    pem = base64.b64decode(pem_b64)
    return serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )


def hybrid_encrypt(message, password=None, use_rsa=False):
    """
    Hybrid encryption using AES and optionally RSA
    Returns encrypted message and keys needed for decryption
    """
    # Use AES for message encryption
    aes = AESCipher(password)
    encrypted_data = aes.encrypt(message)
    
    result = {
        'encrypted_data': encrypted_data,
        'method': 'password' if password else 'key'
    }
    
    # If RSA is requested, encrypt the AES key with RSA
    if use_rsa:
        rsa_cipher = RSACipher()
        result['method'] = 'rsa'
        result['encrypted_key'] = rsa_cipher.encrypt_aes_key(aes.key)
        
        # Serialize the private key to a format that can be stored in JSON
        result['private_key_pem'] = serialize_private_key(rsa_cipher.private_key)
    
    return result


def hybrid_decrypt(encrypted_package, password=None, private_key=None):
    """
    Decrypt a message that was encrypted with hybrid_encrypt
    """
    try:
        method = encrypted_package.get('method', '')
        encrypted_data = encrypted_package.get('encrypted_data', {})
        
        if not method or not encrypted_data:
            raise ValueError("Invalid encrypted package format. Missing method or encrypted_data.")
        
        if method == 'password' or method == 'aes':
            # Password-based decryption
            if not password:
                raise ValueError("Password required for decryption")
            aes = AESCipher()
            plaintext = aes.decrypt(encrypted_data, password)
        elif method == 'key':
            # Direct key decryption
            if 'key' not in encrypted_package:
                raise ValueError("Missing key in encrypted package")
            aes = AESCipher()
            aes.key = encrypted_package['key']
            plaintext = aes.decrypt(encrypted_data)
        elif method == 'rsa' or method == 'aes_rsa':
            # RSA-based key decryption
            if 'private_key_pem' not in encrypted_package:
                raise ValueError("Missing private key for RSA decryption")
            
            # Deserialize the private key
            private_key = deserialize_private_key(encrypted_package['private_key_pem'])
            
            rsa_cipher = RSACipher()
            rsa_cipher.private_key = private_key
            
            if 'encrypted_key' not in encrypted_package:
                raise ValueError("Missing encrypted key in package")
            
            aes_key = rsa_cipher.decrypt_aes_key(encrypted_package['encrypted_key'])
            
            aes = AESCipher()
            aes.key = aes_key
            plaintext = aes.decrypt(encrypted_data)
        else:
            raise ValueError(f"Unknown decryption method: {method}")
        
        return plaintext
    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")