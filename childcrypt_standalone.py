#!/usr/bin/env python3
"""
ChildCrypt - A Modern Stream Cipher Implementation (Standalone Version)

This is an improved version of childcrypt that implements a proper stream cipher
with strong cryptographic properties using only Python standard library:
- SHA-256 based keystream generation
- Proper key derivation and stretching using PBKDF2
- Secure random number generation
- Binary data support
- Authenticated encryption option using HMAC

Author: Julio Oña <thinmanj@gmail.com> (Improved by AI Assistant)
License: MIT
"""

import os
import hashlib
import hmac
import secrets
from typing import Union, Tuple, Optional


class ChildCrypt:
    """A modern stream cipher implementation using only standard library."""
    
    def __init__(self, key: Union[str, bytes], salt: Optional[bytes] = None):
        """
        Initialize the cipher with a key and optional salt.
        
        Args:
            key: The encryption key (string or bytes)
            salt: Optional salt for key derivation (16 bytes recommended)
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        if len(key) < 8:
            raise ValueError("Key must be at least 8 characters/bytes long")
        
        self.salt = salt if salt is not None else os.urandom(16)
        self.derived_key = self._derive_key(key, self.salt)
        
    def _derive_key(self, key: bytes, salt: bytes) -> bytes:
        """Derive a strong key from the input using PBKDF2."""
        return hashlib.pbkdf2_hmac('sha256', key, salt, 100000, 32)
    
    def _generate_keystream(self, length: int, nonce: bytes) -> bytes:
        """
        Generate a keystream using SHA-256 in counter mode.
        
        Args:
            length: Length of keystream to generate
            nonce: Unique number used once (12 bytes)
        
        Returns:
            Generated keystream bytes
        """
        keystream = bytearray()
        counter = 0
        
        while len(keystream) < length:
            # Create block input: key + nonce + counter
            block_input = self.derived_key + nonce + counter.to_bytes(4, 'little')
            
            # Hash the block input to create keystream block
            block = hashlib.sha256(block_input).digest()
            keystream.extend(block)
            counter += 1
            
        return bytes(keystream[:length])
    
    def encrypt(self, data: Union[str, bytes], nonce: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using the stream cipher.
        
        Args:
            data: Data to encrypt (string or bytes)
            nonce: Optional nonce (12 bytes). If None, a random nonce is generated.
        
        Returns:
            Tuple of (encrypted_data, nonce)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if nonce is None:
            nonce = os.urandom(12)
        elif len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes")
        
        # Generate keystream
        keystream = self._generate_keystream(len(data), nonce)
        
        # XOR data with keystream
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))
        
        return encrypted, nonce
    
    def decrypt(self, encrypted_data: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using the stream cipher.
        
        Args:
            encrypted_data: The encrypted data to decrypt
            nonce: The nonce used during encryption (12 bytes)
        
        Returns:
            Decrypted data as bytes
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes")
        
        # Generate the same keystream
        keystream = self._generate_keystream(len(encrypted_data), nonce)
        
        # XOR encrypted data with keystream to decrypt
        decrypted = bytes(a ^ b for a, b in zip(encrypted_data, keystream))
        
        return decrypted
    
    def encrypt_with_auth(self, data: Union[str, bytes], nonce: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data with authentication (HMAC).
        
        Args:
            data: Data to encrypt
            nonce: Optional nonce
        
        Returns:
            Tuple of (encrypted_data, nonce, auth_tag)
        """
        encrypted_data, nonce = self.encrypt(data, nonce)
        
        # Create HMAC for authentication
        auth_key = hashlib.sha256(self.derived_key + b'auth').digest()
        auth_tag = hmac.new(auth_key, encrypted_data + nonce, hashlib.sha256).digest()
        
        return encrypted_data, nonce, auth_tag
    
    def decrypt_with_auth(self, encrypted_data: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """
        Decrypt data with authentication verification.
        
        Args:
            encrypted_data: The encrypted data
            nonce: The nonce used during encryption
            auth_tag: The authentication tag
        
        Returns:
            Decrypted data as bytes
        
        Raises:
            ValueError: If authentication fails
        """
        # Verify authentication
        auth_key = hashlib.sha256(self.derived_key + b'auth').digest()
        expected_tag = hmac.new(auth_key, encrypted_data + nonce, hashlib.sha256).digest()
        
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("Authentication failed - data may have been tampered with")
        
        return self.decrypt(encrypted_data, nonce)


# Legacy compatibility layer for the original API
class LegacyChildCrypt:
    """Provides compatibility with the original childcrypt API while using secure implementation."""
    
    def __init__(self, key: str = "secure_default_key_2024"):
        self.cipher = ChildCrypt(key)
        # Store the key and nonce for legacy compatibility
        self._current_nonce = None
    
    def crypt(self, data: str) -> str:
        """Legacy encrypt function - returns base64 encoded result."""
        import base64
        encrypted, nonce = self.cipher.encrypt(data)
        self._current_nonce = nonce
        # Return base64 encoded data + nonce for easy handling
        combined = encrypted + nonce
        return base64.b64encode(combined).decode('ascii')
    
    def decrypt(self, encrypted_b64: str) -> str:
        """Legacy decrypt function - expects base64 encoded input."""
        import base64
        try:
            combined = base64.b64decode(encrypted_b64.encode('ascii'))
            # Split the data and nonce (nonce is last 12 bytes)
            encrypted_data = combined[:-12]
            nonce = combined[-12:]
            decrypted = self.cipher.decrypt(encrypted_data, nonce)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


def demo():
    """Demonstration of the improved cipher capabilities."""
    print("=== ChildCrypt Standalone Demo ===")
    
    # Test with the original example
    original_text = "An example of text, for a simple crypt function 'childcrypt'."
    password = "my_secure_password_123"
    
    print(f"Original text: {original_text}")
    print(f"Password: {password}")
    print()
    
    # Initialize cipher
    cipher = ChildCrypt(password)
    print(f"Salt (hex): {cipher.salt.hex()}")
    
    # Basic encryption/decryption
    print("\n--- Basic Encryption ---")
    encrypted_data, nonce = cipher.encrypt(original_text)
    print(f"Encrypted (hex): {encrypted_data.hex()}")
    print(f"Nonce (hex): {nonce.hex()}")
    
    decrypted_data = cipher.decrypt(encrypted_data, nonce)
    print(f"Decrypted: {decrypted_data.decode('utf-8')}")
    print(f"Match: {original_text == decrypted_data.decode('utf-8')}")
    
    # Authenticated encryption
    print("\n--- Authenticated Encryption ---")
    enc_data, nonce, auth_tag = cipher.encrypt_with_auth(original_text)
    print(f"Encrypted (hex): {enc_data.hex()}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Auth tag (hex): {auth_tag.hex()}")
    
    try:
        dec_data = cipher.decrypt_with_auth(enc_data, nonce, auth_tag)
        print(f"Authenticated decryption: {dec_data.decode('utf-8')}")
        print(f"Match: {original_text == dec_data.decode('utf-8')}")
    except ValueError as e:
        print(f"Authentication error: {e}")
    
    # Test with binary data
    print("\n--- Binary Data Test ---")
    binary_data = os.urandom(50)
    print(f"Original binary length: {len(binary_data)} bytes")
    
    enc_bin, nonce_bin = cipher.encrypt(binary_data)
    dec_bin = cipher.decrypt(enc_bin, nonce_bin)
    print(f"Binary match: {binary_data == dec_bin}")
    
    # Legacy compatibility test
    print("\n--- Legacy Compatibility Test ---")
    legacy = LegacyChildCrypt("test_key_123")
    legacy_encrypted = legacy.crypt(original_text)
    print(f"Legacy encrypted: {legacy_encrypted}")
    
    legacy_decrypted = legacy.decrypt(legacy_encrypted)
    print(f"Legacy decrypted: {legacy_decrypted}")
    print(f"Legacy match: {original_text == legacy_decrypted}")
    
    # Security test - tampering detection
    print("\n--- Tampering Detection Test ---")
    enc_data, nonce, auth_tag = cipher.encrypt_with_auth("Secret message")
    
    # Tamper with the encrypted data
    tampered_data = bytearray(enc_data)
    tampered_data[0] ^= 1  # Flip a bit
    
    try:
        cipher.decrypt_with_auth(bytes(tampered_data), nonce, auth_tag)
        print("ERROR: Tampering not detected!")
    except ValueError:
        print("SUCCESS: Tampering correctly detected and blocked")
    
    print("\n=== Demo Complete ===")


def benchmark():
    """Simple benchmark to show performance."""
    import time
    
    print("\n=== Performance Benchmark ===")
    cipher = ChildCrypt("benchmark_key")
    
    # Test different data sizes
    sizes = [100, 1000, 10000, 100000]
    
    for size in sizes:
        data = os.urandom(size)
        
        # Measure encryption time
        start_time = time.time()
        encrypted, nonce = cipher.encrypt(data)
        encrypt_time = time.time() - start_time
        
        # Measure decryption time
        start_time = time.time()
        decrypted = cipher.decrypt(encrypted, nonce)
        decrypt_time = time.time() - start_time
        
        # Verify correctness
        assert data == decrypted
        
        throughput = size / (encrypt_time + decrypt_time) / 1024 / 1024  # MB/s
        print(f"{size:6d} bytes: {encrypt_time*1000:6.2f}ms encrypt, {decrypt_time*1000:6.2f}ms decrypt, {throughput:6.2f} MB/s")


if __name__ == '__main__':
    demo()
    benchmark()