"""
Tests for secure messaging module
"""

import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest
from src.messaging.messaging import MessagingModule
from cryptography.hazmat.primitives import serialization


class TestMessagingModule:
    """Test secure messaging functionality"""
    
    def test_generate_keypair(self):
        """Test ECDH key pair generation"""
        msg = MessagingModule()
        private_key, public_key_bytes = msg.generate_keypair()
        
        assert private_key is not None
        assert public_key_bytes is not None
        assert isinstance(public_key_bytes, bytes)
        assert b'BEGIN PUBLIC KEY' in public_key_bytes
    
    def test_derive_shared_secret(self):
        """Test ECDH shared secret derivation"""
        msg = MessagingModule()
        
        # Generate two key pairs
        alice_private, alice_public = msg.generate_keypair()
        bob_private, bob_public = msg.generate_keypair()
        
        # Both should derive the same shared secret
        alice_secret = msg.derive_shared_secret(alice_private, bob_public)
        bob_secret = msg.derive_shared_secret(bob_private, alice_public)
        
        assert alice_secret == bob_secret
        assert len(alice_secret) == 32  # P-256 produces 32-byte shared secret
    
    def test_derive_aes_key(self):
        """Test HKDF key derivation"""
        msg = MessagingModule()
        shared_secret = b'\x00' * 32
        
        # Derive with default salt
        key1 = msg.derive_aes_key(shared_secret)
        assert len(key1) == 32
        
        # Derive with specific salt
        salt = b'\x01' * 32
        key2 = msg.derive_aes_key(shared_secret, salt)
        assert len(key2) == 32
        assert key1 != key2  # Different salts produce different keys
    
    def test_encrypt_decrypt_message(self):
        """Test end-to-end message encryption and decryption"""
        msg = MessagingModule()
        
        # Generate key pairs for Alice and Bob
        alice_private, alice_public = msg.generate_keypair()
        bob_private, bob_public = msg.generate_keypair()
        
        # Alice encrypts message for Bob
        message = "Hello, Bob! This is a secret message."
        encrypted = msg.encrypt_message(bob_public, message, alice_private)
        
        # Verify encrypted structure
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted
        assert 'auth_tag' in encrypted
        assert 'ephemeral_pubkey' in encrypted
        assert 'signature' in encrypted
        assert 'salt' in encrypted
        
        # Bob decrypts message
        decrypted = msg.decrypt_message(encrypted, bob_private, alice_public)
        
        assert decrypted == message
    
    def test_signature_verification(self):
        """Test ECDSA signature generation and verification"""
        msg = MessagingModule()
        
        # Generate key pair
        private_key, public_key_bytes = msg.generate_keypair()
        
        # Sign a message
        message = b"Test message to sign"
        signature = msg.sign_message(private_key, message)
        
        assert signature is not None
        assert len(signature) > 0
        
        # Verify signature
        assert msg.verify_signature(public_key_bytes, message, signature) is True
        
        # Verify wrong signature fails
        wrong_message = b"Different message"
        assert msg.verify_signature(public_key_bytes, wrong_message, signature) is False
    
    def test_serialize_deserialize_keypair(self):
        """Test key pair serialization"""
        msg = MessagingModule()
        private_key, public_key_bytes = msg.generate_keypair()
        
        # Serialize
        private_pem, public_pem = msg.serialize_keypair(private_key)
        
        assert isinstance(private_pem, str)
        assert isinstance(public_pem, str)
        assert 'BEGIN PRIVATE KEY' in private_pem
        assert 'BEGIN PUBLIC KEY' in public_pem
        
        # Deserialize
        deserialized_private = msg.deserialize_private_key(private_pem)
        assert deserialized_private is not None
    
    def test_tamper_detection(self):
        """Test that tampered messages are detected"""
        msg = MessagingModule()
        
        alice_private, alice_public = msg.generate_keypair()
        bob_private, bob_public = msg.generate_keypair()
        
        message = "Secret message"
        encrypted = msg.encrypt_message(bob_public, message, alice_private)
        
        # Tamper with ciphertext
        encrypted['ciphertext'] = '00' * 100
        
        # Decryption should fail
        with pytest.raises(Exception):
            msg.decrypt_message(encrypted, bob_private, alice_public)
    
    def test_wrong_recipient_fails(self):
        """Test that wrong recipient cannot decrypt"""
        msg = MessagingModule()
        
        alice_private, alice_public = msg.generate_keypair()
        bob_private, bob_public = msg.generate_keypair()
        eve_private, eve_public = msg.generate_keypair()
        
        # Alice encrypts for Bob
        message = "Secret for Bob"
        encrypted = msg.encrypt_message(bob_public, message, alice_private)
        
        # Eve tries to decrypt (should fail)
        with pytest.raises(Exception):
            msg.decrypt_message(encrypted, eve_private, alice_public)
    
    def test_ratcheting(self):
        """Test perfect forward secrecy with ratcheting"""
        msg = MessagingModule()
        
        # Initialize ratchet from shared secret
        shared_secret = b'\x00' * 32
        ratchet_state = msg.init_ratchet(shared_secret)
        
        assert 'root_key' in ratchet_state
        assert 'chain_key' in ratchet_state
        assert 'position' in ratchet_state
        
        # Encrypt multiple messages
        message1 = "Message 1"
        ratchet_state, encrypted1 = msg.ratchet_encrypt(ratchet_state, message1)
        
        message2 = "Message 2"
        ratchet_state, encrypted2 = msg.ratchet_encrypt(ratchet_state, message2)
        
        # Verify different nonces
        assert encrypted1['nonce'] != encrypted2['nonce']
        
        # Decrypt (need to reset state for demo)
        ratchet_state2 = msg.init_ratchet(shared_secret)
        _, decrypted1 = msg.ratchet_decrypt(ratchet_state2, encrypted1)
        ratchet_state2, _ = msg.ratchet_decrypt(ratchet_state2, encrypted1)
        _, decrypted2 = msg.ratchet_decrypt(ratchet_state2, encrypted2)
        
        assert decrypted1 == message1
        assert decrypted2 == message2
    
    def test_group_messaging(self):
        """Test group messaging with shared key"""
        msg = MessagingModule()
        
        # Generate group key
        group_key = msg.generate_group_key()
        assert len(group_key) == 64  # 32 bytes = 64 hex chars
        
        # Encrypt message
        message = "Group message"
        encrypted = msg.encrypt_group_message(group_key, message)
        
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted
        assert 'auth_tag' in encrypted
        
        # Decrypt message
        decrypted = msg.decrypt_group_message(encrypted, group_key)
        assert decrypted == message
        
        # Wrong key should fail
        wrong_key = msg.generate_group_key()
        assert msg.decrypt_group_message(encrypted, wrong_key) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

