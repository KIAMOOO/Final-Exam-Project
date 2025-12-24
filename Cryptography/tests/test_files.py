"""
Tests for file encryption module
"""

import sys
from pathlib import Path
import tempfile
import os

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest
from src.files.file_encryption import FileEncryptionModule


class TestFileEncryptionModule:
    """Test file encryption functionality"""
    
    def test_derive_master_key(self):
        """Test PBKDF2 key derivation"""
        file_module = FileEncryptionModule()
        
        password = "TestPassword123!"
        master_key1, salt1 = file_module.derive_master_key(password)
        
        assert len(master_key1) == 32
        assert len(salt1) == 32
        
        # Same password, different salt = different key
        master_key2, salt2 = file_module.derive_master_key(password)
        assert master_key1 != master_key2  # Different salts
        
        # Same password and salt = same key
        master_key3, _ = file_module.derive_master_key(password, salt1)
        assert master_key1 == master_key3
    
    def test_pbkdf2_iterations(self):
        """Test that PBKDF2 uses minimum iterations"""
        # Should fail with too few iterations
        with pytest.raises(ValueError):
            FileEncryptionModule(pbkdf2_iterations=50000)
        
        # Should work with 100k+ iterations
        file_module = FileEncryptionModule(pbkdf2_iterations=100000)
        assert file_module.pbkdf2_iterations == 100000
    
    def test_generate_file_encryption_key(self):
        """Test FEK generation"""
        file_module = FileEncryptionModule()
        
        fek1 = file_module.generate_file_encryption_key()
        fek2 = file_module.generate_file_encryption_key()
        
        assert len(fek1) == 32
        assert len(fek2) == 32
        assert fek1 != fek2  # Should be random
    
    def test_encrypt_decrypt_fek(self):
        """Test FEK encryption with master key"""
        file_module = FileEncryptionModule()
        
        master_key = b'\x00' * 32
        fek = b'\x01' * 32
        
        # Encrypt FEK
        encrypted_fek, nonce = file_module.encrypt_fek_with_master_key(fek, master_key)
        
        assert len(encrypted_fek) == 48  # 32 bytes + 16 byte auth tag
        assert len(nonce) == 12
        
        # Decrypt FEK
        decrypted_fek = file_module.decrypt_fek_with_master_key(encrypted_fek, master_key, nonce)
        
        assert decrypted_fek == fek
    
    def test_compute_file_hash(self):
        """Test SHA-256 file hashing"""
        file_module = FileEncryptionModule()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test file content for hashing"
            f.write(test_data)
            temp_path = f.name
        
        try:
            file_hash = file_module.compute_file_hash(temp_path)
            
            assert len(file_hash) == 64  # SHA-256 = 64 hex chars
            assert isinstance(file_hash, str)
            
            # Same file should produce same hash
            file_hash2 = file_module.compute_file_hash(temp_path)
            assert file_hash == file_hash2
        finally:
            os.unlink(temp_path)
    
    def test_compute_hmac(self):
        """Test HMAC-SHA256 computation"""
        file_module = FileEncryptionModule()
        
        data = b"Test data"
        key = b'\x00' * 32
        
        hmac1 = file_module.compute_hmac(data, key)
        
        assert len(hmac1) == 32  # SHA-256 = 32 bytes
        assert isinstance(hmac1, bytes)
        
        # Same data and key = same HMAC
        hmac2 = file_module.compute_hmac(data, key)
        assert hmac1 == hmac2
        
        # Different data = different HMAC
        hmac3 = file_module.compute_hmac(b"Different data", key)
        assert hmac1 != hmac3
    
    def test_encrypt_decrypt_file(self):
        """Test full file encryption and decryption"""
        file_module = FileEncryptionModule()
        
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            original_content = b"This is a test file with some content to encrypt."
            f.write(original_content)
            original_path = f.name
        
        encrypted_path = original_path + '.encrypted'
        decrypted_path = original_path + '.decrypted'
        
        try:
            password = "SecurePassword123!"
            
            # Encrypt file
            result = file_module.encrypt_file(original_path, password, encrypted_path)
            
            assert 'encrypted_file' in result
            assert 'file_hash' in result
            assert 'encrypted_hash' in result
            assert 'salt' in result
            assert os.path.exists(encrypted_path)
            
            # Verify encrypted file is different
            assert os.path.getsize(encrypted_path) > os.path.getsize(original_path)
            
            # Decrypt file
            success, error_msg = file_module.decrypt_file(encrypted_path, password, decrypted_path)
            
            assert success is True
            assert error_msg is None
            assert os.path.exists(decrypted_path)
            
            # Verify decrypted content matches original
            with open(decrypted_path, 'rb') as f:
                decrypted_content = f.read()
            
            assert decrypted_content == original_content
            
            # Verify hash matches
            decrypted_hash = file_module.compute_file_hash(decrypted_path)
            assert decrypted_hash == result['file_hash']
        finally:
            # Cleanup
            for path in [original_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_large_file_streaming(self):
        """Test streaming encryption for large files"""
        file_module = FileEncryptionModule()
        
        # Create a larger test file (larger than chunk size)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write 200KB of data
            large_content = b"X" * (200 * 1024)
            f.write(large_content)
            original_path = f.name
        
        encrypted_path = original_path + '.encrypted'
        decrypted_path = original_path + '.decrypted'
        
        try:
            password = "TestPassword123!"
            
            # Encrypt
            file_module.encrypt_file(original_path, password, encrypted_path)
            
            # Decrypt
            file_module.decrypt_file(encrypted_path, password, decrypted_path)
            
            # Verify
            with open(decrypted_path, 'rb') as f:
                decrypted_content = f.read()
            
            assert decrypted_content == large_content
        finally:
            for path in [original_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_wrong_password_fails(self):
        """Test that wrong password cannot decrypt"""
        file_module = FileEncryptionModule()
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Secret content")
            original_path = f.name
        
        encrypted_path = original_path + '.encrypted'
        
        try:
            # Encrypt with correct password
            file_module.encrypt_file(original_path, "CorrectPassword123!", encrypted_path)
            
            # Try to decrypt with wrong password
            success, error_msg = file_module.decrypt_file(encrypted_path, "WrongPassword!", "dummy.decrypted")
            assert success is False
            assert error_msg is not None
        finally:
            for path in [original_path, encrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_tamper_detection(self):
        """Test that tampered files are detected"""
        file_module = FileEncryptionModule()
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test content")
            original_path = f.name
        
        encrypted_path = original_path + '.encrypted'
        
        try:
            password = "TestPassword123!"
            file_module.encrypt_file(original_path, password, encrypted_path)
            
            # Read file to find where encrypted data starts
            with open(encrypted_path, 'rb') as f:
                metadata_len = int.from_bytes(f.read(4), 'big')
                metadata_json = f.read(metadata_len)
                data_start = 4 + metadata_len
            
            # Tamper with encrypted data (not metadata)
            with open(encrypted_path, 'r+b') as f:
                f.seek(data_start + 50)  # Skip metadata and some encrypted data
                f.write(b'TAMPERED')
            
            # Decryption should fail due to HMAC verification or decryption error
            success, error_msg = file_module.decrypt_file(encrypted_path, password, "dummy.decrypted")
            assert success is False
            assert error_msg is not None
            # Should fail either at HMAC check or decryption
            assert ("HMAC" in error_msg or "tampered" in error_msg.lower() or 
                   "authenticity" in error_msg.lower() or "corrupted" in error_msg.lower() or
                   "Decryption failed" in error_msg)
        finally:
            for path in [original_path, encrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_integrity_verification(self):
        """Test SHA-256 integrity verification"""
        file_module = FileEncryptionModule()
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            original_content = b"Original file content"
            f.write(original_content)
            original_path = f.name
        
        encrypted_path = original_path + '.encrypted'
        decrypted_path = original_path + '.decrypted'
        
        try:
            password = "TestPassword123!"
            
            # Encrypt and get hash
            encrypt_result = file_module.encrypt_file(original_path, password, encrypted_path)
            original_hash = encrypt_result['file_hash']
            
            # Decrypt and verify hash matches
            success, error_msg = file_module.decrypt_file(encrypted_path, password, decrypted_path)
            
            assert success is True
            assert error_msg is None
            
            # Verify computed hash matches
            computed_hash = file_module.compute_file_hash(decrypted_path)
            assert computed_hash == original_hash
        finally:
            for path in [original_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

