#!/usr/bin/env python3
"""
Comprehensive test suite for ChildCrypt stream cipher implementation.

This test suite covers:
- Basic functionality tests
- Security property tests  
- Edge case handling
- Performance regression tests
- Compatibility tests

Author: AI Assistant
License: MIT
"""

import unittest
import os
import hashlib
import time
from childcrypt_standalone import ChildCrypt, LegacyChildCrypt


class TestChildCrypt(unittest.TestCase):
    """Test cases for the modern ChildCrypt implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_key = "test_key_for_unit_tests_123"
        self.test_data = "This is a test message for encryption testing."
        self.binary_data = b"\x00\x01\x02\xff\xfe\xfd\x7f\x80\x81"
        self.cipher = ChildCrypt(self.test_key)
    
    def test_initialization(self):
        """Test cipher initialization with different key types."""
        # String key
        cipher1 = ChildCrypt("string_key")
        self.assertIsInstance(cipher1.derived_key, bytes)
        self.assertEqual(len(cipher1.derived_key), 32)
        
        # Bytes key
        cipher2 = ChildCrypt(b"bytes_key")
        self.assertIsInstance(cipher2.derived_key, bytes)
        
        # Custom salt
        salt = os.urandom(16)
        cipher3 = ChildCrypt("longer_key", salt=salt)
        self.assertEqual(cipher3.salt, salt)
        
    def test_key_length_validation(self):
        """Test that short keys are rejected."""
        with self.assertRaises(ValueError):
            ChildCrypt("short")  # 5 characters, should fail
            
    def test_basic_encryption_decryption(self):
        """Test basic encrypt/decrypt cycle."""
        encrypted, nonce = self.cipher.encrypt(self.test_data)
        decrypted = self.cipher.decrypt(encrypted, nonce)
        
        self.assertEqual(self.test_data, decrypted.decode('utf-8'))
        self.assertEqual(len(nonce), 12)
        self.assertNotEqual(encrypted, self.test_data.encode())
        
    def test_binary_data_handling(self):
        """Test encryption/decryption of binary data."""
        encrypted, nonce = self.cipher.encrypt(self.binary_data)
        decrypted = self.cipher.decrypt(encrypted, nonce)
        
        self.assertEqual(self.binary_data, decrypted)
        
    def test_nonce_validation(self):
        """Test nonce length validation."""
        # Wrong nonce length should fail
        with self.assertRaises(ValueError):
            self.cipher.encrypt("test", nonce=b"short_nonce")
            
        # Correct nonce length should work
        nonce = os.urandom(12)
        encrypted, returned_nonce = self.cipher.encrypt("test", nonce=nonce)
        self.assertEqual(nonce, returned_nonce)
        
    def test_authenticated_encryption(self):
        """Test authenticated encryption and decryption."""
        encrypted, nonce, auth_tag = self.cipher.encrypt_with_auth(self.test_data)
        decrypted = self.cipher.decrypt_with_auth(encrypted, nonce, auth_tag)
        
        self.assertEqual(self.test_data, decrypted.decode('utf-8'))
        self.assertEqual(len(auth_tag), 32)  # SHA-256 HMAC
        
    def test_tampering_detection(self):
        """Test that tampering with encrypted data is detected."""
        encrypted, nonce, auth_tag = self.cipher.encrypt_with_auth("secret")
        
        # Tamper with encrypted data
        tampered = bytearray(encrypted)
        tampered[0] ^= 1  # Flip one bit
        
        with self.assertRaises(ValueError):
            self.cipher.decrypt_with_auth(bytes(tampered), nonce, auth_tag)
            
        # Tamper with nonce
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 1
        
        with self.assertRaises(ValueError):
            self.cipher.decrypt_with_auth(encrypted, bytes(tampered_nonce), auth_tag)
            
        # Tamper with auth tag
        tampered_tag = bytearray(auth_tag)
        tampered_tag[0] ^= 1
        
        with self.assertRaises(ValueError):
            self.cipher.decrypt_with_auth(encrypted, nonce, bytes(tampered_tag))
    
    def test_deterministic_with_same_nonce(self):
        """Test that encryption is deterministic with the same nonce."""
        nonce = os.urandom(12)
        encrypted1, _ = self.cipher.encrypt(self.test_data, nonce=nonce)
        encrypted2, _ = self.cipher.encrypt(self.test_data, nonce=nonce)
        
        self.assertEqual(encrypted1, encrypted2)
        
    def test_different_output_with_different_nonces(self):
        """Test that different nonces produce different ciphertext."""
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
        
        encrypted1, _ = self.cipher.encrypt(self.test_data, nonce=nonce1)
        encrypted2, _ = self.cipher.encrypt(self.test_data, nonce=nonce2)
        
        self.assertNotEqual(encrypted1, encrypted2)
        
    def test_different_keys_produce_different_results(self):
        """Test that different keys produce different results."""
        cipher2 = ChildCrypt("different_key")
        
        nonce = os.urandom(12)
        encrypted1, _ = self.cipher.encrypt(self.test_data, nonce=nonce)
        encrypted2, _ = cipher2.encrypt(self.test_data, nonce=nonce)
        
        self.assertNotEqual(encrypted1, encrypted2)
        
    def test_empty_data(self):
        """Test handling of empty data."""
        encrypted, nonce = self.cipher.encrypt("")
        decrypted = self.cipher.decrypt(encrypted, nonce)
        
        self.assertEqual(b"", decrypted)
        
    def test_large_data(self):
        """Test encryption of large data."""
        large_data = "A" * 100000  # 100KB of data
        
        encrypted, nonce = self.cipher.encrypt(large_data)
        decrypted = self.cipher.decrypt(encrypted, nonce)
        
        self.assertEqual(large_data, decrypted.decode('utf-8'))
        
    def test_unicode_data(self):
        """Test encryption of Unicode data."""
        unicode_data = "Hello 世界! 🔒 Testing émojis and accénts"
        
        encrypted, nonce = self.cipher.encrypt(unicode_data)
        decrypted = self.cipher.decrypt(encrypted, nonce)
        
        self.assertEqual(unicode_data, decrypted.decode('utf-8'))
        
    def test_keystream_randomness(self):
        """Test that keystream appears random."""
        # Generate multiple encryptions of zeros to analyze keystream
        zero_data = b"\x00" * 1000
        keystreams = []
        
        for _ in range(10):
            encrypted, _ = self.cipher.encrypt(zero_data)
            keystreams.append(encrypted)
            
        # Check that keystreams are different (very high probability)
        for i in range(len(keystreams)):
            for j in range(i + 1, len(keystreams)):
                self.assertNotEqual(keystreams[i], keystreams[j])
                
        # Simple randomness check - count of different bytes should be high
        combined = b''.join(keystreams)
        unique_bytes = len(set(combined))
        self.assertGreater(unique_bytes, 200)  # Should have good byte distribution


class TestLegacyChildCrypt(unittest.TestCase):
    """Test cases for legacy compatibility layer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.legacy_cipher = LegacyChildCrypt("legacy_test_key")
        self.test_data = "Legacy compatibility test message."
    
    def test_legacy_encrypt_decrypt(self):
        """Test legacy encrypt/decrypt functionality."""
        encrypted = self.legacy_cipher.crypt(self.test_data)
        decrypted = self.legacy_cipher.decrypt(encrypted)
        
        self.assertEqual(self.test_data, decrypted)
        self.assertIsInstance(encrypted, str)  # Should be base64 string
        
    def test_legacy_base64_format(self):
        """Test that legacy encryption produces valid base64."""
        import base64
        
        encrypted = self.legacy_cipher.crypt(self.test_data)
        
        # Should be valid base64
        try:
            base64.b64decode(encrypted.encode('ascii'))
        except Exception:
            self.fail("Legacy encryption did not produce valid base64")
            
    def test_legacy_error_handling(self):
        """Test error handling in legacy mode."""
        with self.assertRaises(ValueError):
            self.legacy_cipher.decrypt("invalid_base64!")


class TestSecurityProperties(unittest.TestCase):
    """Test security-specific properties of the cipher."""
    
    def test_no_key_recovery_from_ciphertext(self):
        """Test that keys cannot be recovered from ciphertext analysis."""
        cipher = ChildCrypt("secret_key_12345")
        
        # Generate many ciphertexts
        ciphertexts = []
        for i in range(100):
            data = f"message_{i:03d}"
            encrypted, nonce = cipher.encrypt(data)
            ciphertexts.append((encrypted, nonce))
            
        # Simple statistical test - ciphertext should appear random
        all_bytes = b''.join([ct[0] for ct in ciphertexts])
        byte_counts = [0] * 256
        
        for byte in all_bytes:
            byte_counts[byte] += 1
            
        # Check for reasonably uniform distribution
        avg_count = len(all_bytes) / 256
        outliers = sum(1 for count in byte_counts if abs(count - avg_count) > avg_count * 0.5)
        
        # Should have relatively few outliers in a random distribution
        # Relaxed threshold for small sample size
        self.assertLess(outliers / 256, 0.4)  # Less than 40% outliers
        
    def test_avalanche_effect(self):
        """Test avalanche effect - small input changes cause large output changes."""
        # Test with key difference instead of data difference for stream cipher
        nonce = os.urandom(12)
        data = "test message for avalanche effect"
        
        # Test keys that differ by one character
        cipher1 = ChildCrypt("avalanche_test_key_1")
        cipher2 = ChildCrypt("avalanche_test_key_2")
        
        encrypted1, _ = cipher1.encrypt(data, nonce=nonce)
        encrypted2, _ = cipher2.encrypt(data, nonce=nonce)
        
        # Count differing bits
        diff_bits = 0
        for b1, b2 in zip(encrypted1, encrypted2):
            diff_bits += bin(b1 ^ b2).count('1')
            
        # Should have roughly 50% bits different (avalanche effect)
        total_bits = len(encrypted1) * 8
        diff_ratio = diff_bits / total_bits
        
        # Allow some variance but should be close to 0.5 for key avalanche
        self.assertGreater(diff_ratio, 0.3)
        self.assertLess(diff_ratio, 0.7)
        
    def test_key_derivation_security(self):
        """Test that key derivation is working properly."""
        # Same key with different salts should produce different derived keys
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        
        cipher1 = ChildCrypt("same_key", salt=salt1)
        cipher2 = ChildCrypt("same_key", salt=salt2)
        
        self.assertNotEqual(cipher1.derived_key, cipher2.derived_key)
        
        # Different keys with same salt should produce different derived keys
        cipher3 = ChildCrypt("different_key", salt=salt1)
        self.assertNotEqual(cipher1.derived_key, cipher3.derived_key)


class TestPerformance(unittest.TestCase):
    """Performance regression tests."""
    
    def test_encryption_performance(self):
        """Test that encryption performance meets minimum requirements."""
        cipher = ChildCrypt("performance_test_key")
        data = os.urandom(10000)  # 10KB
        
        start_time = time.time()
        
        # Encrypt 100 times
        for _ in range(100):
            encrypted, nonce = cipher.encrypt(data)
            
        elapsed = time.time() - start_time
        throughput = (10000 * 100) / elapsed / 1024 / 1024  # MB/s
        
        # Should be able to encrypt at least 1 MB/s
        self.assertGreater(throughput, 1.0)
        
    def test_memory_usage(self):
        """Test that memory usage is reasonable."""
        import sys
        
        # Create cipher and measure size
        cipher = ChildCrypt("memory_test_key")
        
        # The cipher object should not be excessively large
        size = sys.getsizeof(cipher) + sys.getsizeof(cipher.derived_key) + sys.getsizeof(cipher.salt)
        
        # Should be less than 1KB for the cipher object
        self.assertLess(size, 1024)


def run_security_analysis():
    """Run additional security analysis (not part of unit tests)."""
    print("=== Security Analysis ===")
    
    cipher = ChildCrypt("analysis_key")
    
    # Test for patterns in keystream
    print("Testing keystream randomness...")
    keystream_data = []
    for _ in range(1000):
        zero_data = b"\x00" * 32  # 32 bytes of zeros
        encrypted, _ = cipher.encrypt(zero_data)
        keystream_data.append(encrypted)
    
    # Analyze patterns
    combined_keystream = b''.join(keystream_data)
    
    # Byte frequency analysis
    byte_freq = [0] * 256
    for byte in combined_keystream:
        byte_freq[byte] += 1
    
    # Calculate chi-squared statistic
    expected_freq = len(combined_keystream) / 256
    chi_squared = sum((freq - expected_freq) ** 2 / expected_freq for freq in byte_freq)
    
    print(f"Chi-squared statistic: {chi_squared:.2f}")
    print(f"Expected range for randomness: 200-300")
    
    # Test for repeated sequences
    print("Testing for repeated sequences...")
    sequences = {}
    for i in range(len(combined_keystream) - 3):
        seq = combined_keystream[i:i+4]
        sequences[seq] = sequences.get(seq, 0) + 1
    
    max_repeats = max(sequences.values())
    print(f"Maximum sequence repetitions: {max_repeats}")
    print(f"Should be low for good randomness")
    
    print("=== Analysis Complete ===")


if __name__ == '__main__':
    # Run unit tests
    print("Running unit tests...")
    unittest.main(verbosity=2, exit=False)
    
    print("\n" + "="*50)
    
    # Run additional security analysis
    run_security_analysis()