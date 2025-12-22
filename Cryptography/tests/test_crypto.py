"""
Tests for core crypto implementations
"""

import pytest
from src.crypto.sha256 import SHA256
from src.crypto.classical import CaesarCipher, VigenereCipher
from src.crypto.rsa import RSAKeyGenerator, modular_exponentiation
from src.crypto.aes_expansion import AESKeyExpansion


class TestSHA256:
    """Test SHA-256 implementation"""
    
    def test_hash_empty_string(self):
        """Test hashing empty string"""
        result = SHA256.hash("")
        assert len(result) == 64  # 256 bits = 64 hex chars
        assert isinstance(result, str)
    
    def test_hash_hello_world(self):
        """Test hashing 'Hello, World!'"""
        result = SHA256.hash("Hello, World!")
        assert len(result) == 64
        assert result == SHA256.hash("Hello, World!")  # Deterministic
    
    def test_hash_bytes(self):
        """Test hashing bytes"""
        result = SHA256.hash(b"test")
        assert len(result) == 64


class TestCaesarCipher:
    """Test Caesar cipher"""
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        plaintext = "HELLO"
        shift = 3
        ciphertext = CaesarCipher.encrypt(plaintext, shift)
        decrypted = CaesarCipher.decrypt(ciphertext, shift)
        assert decrypted == plaintext
    
    def test_break_cipher(self):
        """Test cipher breaking"""
        plaintext = "THEQUICKBROWNFOX"
        shift = 5
        ciphertext = CaesarCipher.encrypt(plaintext, shift)
        results = CaesarCipher.break_cipher(ciphertext)
        assert len(results) == 26
        # Best match should be correct shift
        best_shift, best_decrypted, _ = results[0]
        assert best_shift == shift or best_decrypted == plaintext


class TestVigenereCipher:
    """Test Vigenère cipher"""
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        plaintext = "HELLO"
        key = "KEY"
        ciphertext = VigenereCipher.encrypt(plaintext, key)
        decrypted = VigenereCipher.decrypt(ciphertext, key)
        assert decrypted == plaintext
    
    def test_find_repeated_sequences(self):
        """Test finding repeated sequences"""
        text = "ABCDEFABCDEF"
        sequences = VigenereCipher.find_repeated_sequences(text, min_len=3)
        assert len(sequences) > 0


class TestRSA:
    """Test RSA key generation"""
    
    def test_modular_exponentiation(self):
        """Test modular exponentiation"""
        result = modular_exponentiation(2, 10, 1000)
        assert result == (2 ** 10) % 1000
    
    def test_key_generation(self):
        """Test RSA key pair generation"""
        public_key, private_key = RSAKeyGenerator.generate_keypair(bits=256)
        assert len(public_key) == 2
        assert len(private_key) == 2
        e, n = public_key
        d, n2 = private_key
        assert n == n2
    
    def test_encrypt_decrypt(self):
        """Test RSA encryption and decryption"""
        public_key, private_key = RSAKeyGenerator.generate_keypair(bits=256)
        message = 12345
        ciphertext = RSAKeyGenerator.encrypt(message, public_key)
        decrypted = RSAKeyGenerator.decrypt(ciphertext, private_key)
        assert decrypted == message


class TestAESKeyExpansion:
    """Test AES key expansion"""
    
    def test_expand_128_bit_key(self):
        """Test expanding 128-bit key"""
        key = b'\x00' * 16
        expanded = AESKeyExpansion.expand_key(key, key_size=128)
        assert len(expanded) == 44  # 11 rounds * 4 words
    
    def test_get_round_key(self):
        """Test getting round key"""
        key = b'\x00' * 16
        expanded = AESKeyExpansion.expand_key(key, key_size=128)
        round_key = AESKeyExpansion.get_round_key(expanded, 0)
        assert len(round_key) == 16

