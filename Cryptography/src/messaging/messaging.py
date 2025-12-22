"""
Secure messaging with ECDH key exchange, AES-256-GCM encryption, and ECDSA signatures
"""

import secrets
import json
import hashlib
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class MessagingModule:
    """
    Secure messaging module with end-to-end encryption.
    
    Features:
    - ECDH key exchange using P-256 curve
    - Ephemeral key pairs per session
    - HKDF for shared secret derivation
    - AES-256-GCM authenticated encryption
    - ECDSA signatures for non-repudiation
    """
    
    def __init__(self):
        self.curve = ec.SECP256R1()  # P-256 curve
        self.backend = default_backend()
    
    def generate_keypair(self) -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
        """
        Generate ephemeral ECDH key pair.
        
        Returns:
            Tuple (private_key, public_key_bytes)
        """
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        
        # Serialize public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_key, public_key_bytes
    
    def derive_shared_secret(self, private_key: ec.EllipticCurvePrivateKey, 
                            peer_public_key_bytes: bytes) -> bytes:
        """
        Derive shared secret using ECDH.
        
        Args:
            private_key: Our private key
            peer_public_key_bytes: Peer's public key (PEM format)
            
        Returns:
            Shared secret bytes
        """
        # Deserialize peer's public key
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            self.backend
        )
        
        # Perform ECDH
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        return shared_secret
    
    def derive_aes_key(self, shared_secret: bytes, salt: bytes = None) -> bytes:
        """
        Derive AES key from shared secret using HKDF.
        
        Args:
            shared_secret: ECDH shared secret
            salt: Optional salt (generated if not provided)
            
        Returns:
            32-byte AES key
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'CryptoVault AES Key',
            backend=self.backend
        )
        
        return hkdf.derive(shared_secret)
    
    def encrypt_message(self, recipient_public_key_bytes: bytes, 
                       message: str, sender_private_key: ec.EllipticCurvePrivateKey) -> Dict:
        """
        Encrypt a message for a recipient using hybrid encryption.
        
        This function performs:
        1. ECDH key exchange to derive shared secret
        2. HKDF to derive AES key from shared secret
        3. AES-256-GCM encryption of the message
        4. ECDSA signature on the ciphertext
        
        Args:
            recipient_public_key_bytes: Recipient's ECDSA public key (PEM bytes)
            message: Plaintext message to encrypt (str)
            sender_private_key: Sender's private key for signing
            
        Returns:
            Dictionary containing encrypted message components:
            {
                'nonce': nonce_bytes,
                'ciphertext': encrypted_bytes,
                'auth_tag': auth_tag_bytes,
                'ephemeral_pubkey': sender_ephemeral_pubkey_bytes,
                'signature': signature_bytes
            }
        """
        # Generate ephemeral key pair for this message
        ephemeral_private, ephemeral_public_bytes = self.generate_keypair()
        
        # Derive shared secret
        shared_secret = self.derive_shared_secret(ephemeral_private, recipient_public_key_bytes)
        
        # Derive AES key
        aes_key = self.derive_aes_key(shared_secret)
        
        # Encrypt message with AES-256-GCM
        message_bytes = message.encode('utf-8')
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
        
        # Extract auth tag (last 16 bytes)
        auth_tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        # Sign the ciphertext with sender's private key
        signature = self.sign_message(sender_private_key, ciphertext)
        
        return {
            'nonce': nonce.hex(),
            'ciphertext': encrypted_data.hex(),
            'auth_tag': auth_tag.hex(),
            'ephemeral_pubkey': ephemeral_public_bytes.decode('utf-8'),
            'signature': signature.hex()
        }
    
    def decrypt_message(self, encrypted_data: Dict, 
                       recipient_private_key: ec.EllipticCurvePrivateKey,
                       sender_public_key_bytes: bytes) -> Optional[str]:
        """
        Decrypt a message from a sender.
        
        Args:
            encrypted_data: Dictionary with encrypted message components
            recipient_private_key: Recipient's private key
            sender_public_key_bytes: Sender's public key for verification
            
        Returns:
            Decrypted message string, or None if verification fails
        """
        try:
            # Extract components
            nonce = bytes.fromhex(encrypted_data['nonce'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            auth_tag = bytes.fromhex(encrypted_data['auth_tag'])
            ephemeral_pubkey_bytes = encrypted_data['ephemeral_pubkey'].encode('utf-8')
            signature = bytes.fromhex(encrypted_data['signature'])
            
            # Reconstruct full ciphertext for verification
            full_ciphertext = ciphertext + auth_tag
            
            # Verify signature
            if not self.verify_signature(sender_public_key_bytes, full_ciphertext, signature):
                return None
            
            # Derive shared secret using ephemeral public key
            shared_secret = self.derive_shared_secret(recipient_private_key, ephemeral_pubkey_bytes)
            
            # Derive AES key
            aes_key = self.derive_aes_key(shared_secret)
            
            # Decrypt message
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, None)
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            return None
    
    def sign_message(self, private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
        """
        Sign message hash using ECDSA.
        
        Args:
            private_key: Signer's private key
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        # Hash message
        message_hash = hashlib.sha256(message).digest()
        
        # Sign hash
        signature = private_key.sign(
            message_hash,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        
        return signature
    
    def verify_signature(self, public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify ECDSA signature on message.
        
        Args:
            public_key_bytes: Signer's public key (PEM bytes)
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Deserialize public key
            public_key = serialization.load_pem_public_key(
                public_key_bytes,
                self.backend
            )
            
            # Hash message
            message_hash = hashlib.sha256(message).digest()
            
            # Verify signature
            public_key.verify(
                signature,
                message_hash,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            
            return True
        
        except Exception:
            return False
    
    def serialize_keypair(self, private_key: ec.EllipticCurvePrivateKey) -> Tuple[str, str]:
        """
        Serialize key pair to PEM strings.
        
        Args:
            private_key: Private key to serialize
            
        Returns:
            Tuple (private_key_pem, public_key_pem)
        """
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def deserialize_private_key(self, private_key_pem: str) -> ec.EllipticCurvePrivateKey:
        """
        Deserialize private key from PEM string.
        
        Args:
            private_key_pem: PEM-encoded private key
            
        Returns:
            Private key object
        """
        return serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=self.backend
        )

