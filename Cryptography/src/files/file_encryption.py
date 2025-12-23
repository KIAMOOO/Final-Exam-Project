"""
File encryption system with AES-256-GCM, PBKDF2 key derivation, and integrity verification
"""

import secrets
import hashlib
import hmac
import os
import json
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class FileEncryptionModule:
    """
    File encryption module for secure file storage.
    
    Features:
    - AES-256-GCM encryption for files
    - PBKDF2 key derivation with 100,000+ iterations
    - SHA-256 hash for file integrity
    - HMAC-SHA256 for authenticity verification
    - Streaming encryption for large files
    """
    
    def __init__(self, pbkdf2_iterations: int = 100000):
        """
        Initialize file encryption module.
        
        Args:
            pbkdf2_iterations: Number of PBKDF2 iterations (minimum 100,000)
        """
        if pbkdf2_iterations < 100000:
            raise ValueError("PBKDF2 iterations must be at least 100,000")
        
        self.pbkdf2_iterations = pbkdf2_iterations
        self.backend = default_backend()
        self.chunk_size = 64 * 1024  # 64 KB chunks for streaming
    
    def derive_master_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive master key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple (master_key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=self.backend
        )
        
        master_key = kdf.derive(password.encode('utf-8'))
        return master_key, salt
    
    def generate_file_encryption_key(self) -> bytes:
        """
        Generate random file encryption key (FEK).
        
        Returns:
            32-byte encryption key
        """
        return secrets.token_bytes(32)
    
    def encrypt_fek_with_master_key(self, fek: bytes, master_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt file encryption key with master key.
        
        Args:
            fek: File encryption key
            master_key: Master key
            
        Returns:
            Tuple (encrypted_fek, nonce)
        """
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(master_key)
        encrypted_fek = aesgcm.encrypt(nonce, fek, None)
        
        # Extract auth tag
        auth_tag = encrypted_fek[-16:]
        encrypted_data = encrypted_fek[:-16]
        
        return encrypted_data + auth_tag, nonce
    
    def decrypt_fek_with_master_key(self, encrypted_fek: bytes, master_key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt file encryption key with master key.
        
        Args:
            encrypted_fek: Encrypted file encryption key
            master_key: Master key
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted file encryption key
        """
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, encrypted_fek, None)
    
    def compute_file_hash(self, file_path: str) -> str:
        """
        Compute SHA-256 hash of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hexadecimal hash string
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def compute_file_hash_bytes(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash of data.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash bytes
        """
        return hashlib.sha256(data).digest()
    
    def compute_hmac(self, data: bytes, key: bytes) -> bytes:
        """
        Compute HMAC-SHA256 of data.
        
        Args:
            data: Data to authenticate
            key: HMAC key
            
        Returns:
            HMAC bytes
        """
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def encrypt_file(self, file_path: str, password: str, output_path: str = None) -> dict:
        """
        Encrypt a file with integrity verification.
        
        Process:
        1. Compute SHA-256 hash of original file
        2. Derive master key from password
        3. Generate file encryption key (FEK)
        4. Encrypt FEK with master key
        5. Encrypt file with FEK using AES-256-GCM
        6. Compute HMAC for authenticity
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            output_path: Optional output path (default: file_path.encrypted)
            
        Returns:
            Dictionary with encryption metadata:
            {
                'encrypted_file': path,
                'file_hash': original_hash,
                'encrypted_hash': encrypted_hash,
                'salt': master_key_salt,
                'fek_nonce': fek_nonce,
                'hmac': hmac_value
            }
        """
        if output_path is None:
            output_path = file_path + '.encrypted'
        
        # Compute original file hash
        original_hash = self.compute_file_hash(file_path)
        
        # Derive master key
        master_key, master_salt = self.derive_master_key(password)
        
        # Generate file encryption key
        fek = self.generate_file_encryption_key()
        
        # Encrypt FEK with master key
        encrypted_fek, fek_nonce = self.encrypt_fek_with_master_key(fek, master_key)
        
        # Encrypt file data in streaming mode and collect encrypted chunks
        initial_nonce = secrets.token_bytes(12)
        nonce = initial_nonce
        aesgcm = AESGCM(fek)

        encrypted_chunks = []
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                encrypted_chunks.append(encrypted_chunk)
                # Use new nonce for each chunk (increment)
                nonce = int.from_bytes(nonce, 'big')
                nonce = (nonce + 1) % (2**96)
                nonce = nonce.to_bytes(12, 'big')

        # Compute SHA-256 over all encrypted chunks (ciphertext + tags)
        # This value is used for HMAC-based authenticity and stored in metadata.
        enc_sha = hashlib.sha256()
        for chunk in encrypted_chunks:
            enc_sha.update(chunk)
        encrypted_hash = enc_sha.hexdigest()

        # Compute HMAC-SHA256 over encrypted_hash using the master key
        hmac_value = self.compute_hmac(encrypted_hash.encode(), master_key)

        # Write encrypted file with metadata header (including HMAC)
        with open(output_path, 'wb') as f:
            metadata = {
                'master_salt': master_salt.hex(),
                'encrypted_fek': encrypted_fek.hex(),
                'fek_nonce': fek_nonce.hex(),
                'initial_nonce': initial_nonce.hex(),
                'original_hash': original_hash,
                'chunk_count': len(encrypted_chunks),
                'encrypted_hash': encrypted_hash,
                'hmac': hmac_value.hex(),
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            f.write(len(metadata_json).to_bytes(4, 'big'))
            f.write(metadata_json)

            # Write encrypted chunks
            for chunk in encrypted_chunks:
                f.write(chunk)

        return {
            'encrypted_file': output_path,
            'file_hash': original_hash,
            'encrypted_hash': encrypted_hash,
            'salt': master_salt.hex(),
            'fek_nonce': fek_nonce.hex(),
            'hmac': hmac_value.hex()
        }
    
    def decrypt_file(self, encrypted_file_path: str, password: str, output_path: str = None) -> Tuple[bool, Optional[str]]:
        """
        Decrypt a file and verify integrity.
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Decryption password
            output_path: Optional output path
            
        Returns:
            Tuple (success, error_message)
        """
        try:
            # Check if file exists
            if not os.path.exists(encrypted_file_path):
                return False, f"Encrypted file not found: {encrypted_file_path}"
            
            if output_path is None:
                if encrypted_file_path.endswith('.encrypted'):
                    output_path = encrypted_file_path[:-10]
                else:
                    output_path = encrypted_file_path + '.decrypted'
            
            with open(encrypted_file_path, 'rb') as f:
                # Read metadata
                metadata_len_bytes = f.read(4)
                if len(metadata_len_bytes) < 4:
                    return False, "Invalid encrypted file format - missing metadata length"
                
                metadata_len = int.from_bytes(metadata_len_bytes, 'big')
                metadata_json = f.read(metadata_len).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                # Check for required metadata fields (older files may not have all of them)
                required_fields = ['master_salt', 'encrypted_fek', 'fek_nonce', 'original_hash']
                for field in required_fields:
                    if field not in metadata:
                        return False, f"Invalid encrypted file format - missing {field}"
                
                # Derive master key
                master_salt = bytes.fromhex(metadata['master_salt'])
                master_key, _ = self.derive_master_key(password, master_salt)
                
                # Decrypt FEK
                encrypted_fek = bytes.fromhex(metadata['encrypted_fek'])
                fek_nonce = bytes.fromhex(metadata['fek_nonce'])
                try:
                    fek = self.decrypt_fek_with_master_key(encrypted_fek, master_key, fek_nonce)
                except Exception as e:
                    return False, "Decryption failed - incorrect password or corrupted file"

                # HMAC-based authenticity verification (if HMAC is present in metadata)
                stored_encrypted_hash = metadata.get('encrypted_hash')
                stored_hmac_hex = metadata.get('hmac')
                verify_hmac = bool(stored_encrypted_hash and stored_hmac_hex)
                if verify_hmac:
                    try:
                        stored_hmac = bytes.fromhex(stored_hmac_hex)
                    except ValueError:
                        return False, "Invalid HMAC value in encrypted file metadata"

                # Prepare for decrypting chunks and optionally recomputing encrypted_hash
                enc_sha = hashlib.sha256() if verify_hmac else None

                # Read and decrypt chunks
                aesgcm = AESGCM(fek)
                # Use the same initial nonce from encryption
                if 'initial_nonce' not in metadata:
                    return False, "File was encrypted with an older version. Please re-encrypt the file."
                nonce = bytes.fromhex(metadata['initial_nonce'])
                
                decrypted_chunks = []
                chunk_count = metadata.get('chunk_count', 1)
                
                for i in range(chunk_count):
                    # Read chunk (encrypted chunk includes auth tag, so it's larger)
                    chunk = f.read(self.chunk_size + 16)  # +16 for auth tag
                    if not chunk:
                        break

                    # Update encrypted hash computation for HMAC if enabled
                    if enc_sha is not None:
                        enc_sha.update(chunk)

                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        decrypted_chunks.append(decrypted_chunk)

                        # Increment nonce for next chunk
                        nonce = int.from_bytes(nonce, 'big')
                        nonce = (nonce + 1) % (2**96)
                        nonce = nonce.to_bytes(12, 'big')
                    except Exception:
                        return False, "Decryption failed - file may be corrupted or password incorrect"

                # Write decrypted file
                with open(output_path, 'wb') as out_f:
                    for chunk in decrypted_chunks:
                        out_f.write(chunk)

                # If HMAC metadata is present, verify authenticity of encrypted data
                if enc_sha is not None:
                    encrypted_hash = enc_sha.hexdigest()
                    expected_hmac = self.compute_hmac(encrypted_hash.encode(), master_key)
                    if not hmac.compare_digest(expected_hmac, stored_hmac):
                        if os.path.exists(output_path):
                            os.remove(output_path)
                        return False, "File authenticity check failed - HMAC mismatch (file may be corrupted or tampered with)"

                # Verify original hash
                decrypted_hash = self.compute_file_hash(output_path)
                if decrypted_hash != metadata['original_hash']:
                    os.remove(output_path)
                    return False, "Integrity check failed - file may have been tampered with"
                
                return True, None
        
        except Exception as e:
            return False, f"Decryption error: {str(e)}"
    
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify file integrity using SHA-256 hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value
            
        Returns:
            True if hash matches, False otherwise
        """
        actual_hash = self.compute_file_hash(file_path)
        return hmac.compare_digest(actual_hash, expected_hash)

