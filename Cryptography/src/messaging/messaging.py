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
            peer_public_key_bytes: Peer's public key (PEM format, bytes or str)
            
        Returns:
            Shared secret bytes
        """
        # Normalize to bytes if string
        if isinstance(peer_public_key_bytes, str):
            peer_public_key_bytes = peer_public_key_bytes.strip().encode('utf-8')
        else:
            # Normalize bytes - remove any extra whitespace
            peer_public_key_bytes = peer_public_key_bytes.strip()
        
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
                'signature': signature_bytes,
                'salt': salt_bytes (hex)
            }
        """
        # Generate ephemeral key pair for this message
        ephemeral_private, ephemeral_public_bytes = self.generate_keypair()
        
        # Derive shared secret
        shared_secret = self.derive_shared_secret(ephemeral_private, recipient_public_key_bytes)
        
        # Generate salt for HKDF
        salt = secrets.token_bytes(32)
        
        # Derive AES key with specific salt
        aes_key = self.derive_aes_key(shared_secret, salt)
        
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
            'signature': signature.hex(),
            'salt': salt.hex()
        }
    
    def decrypt_message(self, encrypted_data: Dict, 
                       recipient_private_key: ec.EllipticCurvePrivateKey,
                       sender_public_key_bytes: bytes) -> Optional[str]:
        """
        Decrypt a message from a sender.
        
        Args:
            encrypted_data: Dictionary with encrypted message components
            recipient_private_key: Recipient's private key
            sender_public_key_bytes: Sender's public key for verification (bytes or str)
            
        Returns:
            Decrypted message string, or None if verification fails
        """
        try:
            # Normalize sender public key
            if isinstance(sender_public_key_bytes, str):
                sender_public_key_bytes = sender_public_key_bytes.strip().encode('utf-8')
            else:
                sender_public_key_bytes = sender_public_key_bytes.strip()
            
            # Extract components
            nonce = bytes.fromhex(encrypted_data['nonce'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            auth_tag = bytes.fromhex(encrypted_data['auth_tag'])
            # Normalize ephemeral pubkey
            ephemeral_pubkey_str = encrypted_data['ephemeral_pubkey'].strip() if isinstance(encrypted_data['ephemeral_pubkey'], str) else encrypted_data['ephemeral_pubkey'].decode('utf-8').strip()
            ephemeral_pubkey_bytes = ephemeral_pubkey_str.encode('utf-8')
            signature = bytes.fromhex(encrypted_data['signature'])
            
            # Get salt if present (for backward compatibility)
            salt = None
            if 'salt' in encrypted_data:
                salt = bytes.fromhex(encrypted_data['salt'])
            
            # Reconstruct full ciphertext for verification
            full_ciphertext = ciphertext + auth_tag
            
            # Verify signature
            if not self.verify_signature(sender_public_key_bytes, full_ciphertext, signature):
                raise Exception("Signature verification failed. Make sure you're using the correct sender's public key.")
            
            # Derive shared secret using ephemeral public key
            shared_secret = self.derive_shared_secret(recipient_private_key, ephemeral_pubkey_bytes)
            
            # Derive AES key using the same salt as encryption
            aes_key = self.derive_aes_key(shared_secret, salt)
            
            # Decrypt message
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, None)
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            # Re-raise exception with details for debugging
            raise Exception(f"Decryption error: {str(e)}")
    
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
            public_key_bytes: Signer's public key (PEM bytes or str)
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Normalize public key bytes
            if isinstance(public_key_bytes, str):
                public_key_bytes = public_key_bytes.strip().encode('utf-8')
            else:
                public_key_bytes = public_key_bytes.strip()
            
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
        # Strip whitespace to avoid deserialization errors from copy/paste
        normalized = private_key_pem.strip().encode('utf-8')
        return serialization.load_pem_private_key(
            normalized,
            password=None,
            backend=self.backend
        )

    # ------------------------------------------------------------------
    # Bonus Feature 1: Simple Ratcheting for Perfect Forward Secrecy
    # ------------------------------------------------------------------
    def init_ratchet(self, shared_secret: bytes) -> Dict[str, str]:
        """
        Initialize a simple symmetric ratchet state from an existing shared secret.
        
        This can be used on top of an existing ECDH shared secret to provide
        per-message keys without changing the core API.
        """
        root_key = hashlib.sha256(shared_secret + b"cryptovault-ratchet-root").digest()
        chain_key = hashlib.sha256(root_key + b"chain-0").digest()
        return {
            "root_key": root_key.hex(),
            "chain_key": chain_key.hex(),
            "position": 0,
        }
    
    def _ratchet_step(self, chain_key: bytes, position: int) -> Tuple[bytes, bytes]:
        """
        Derive next chain key and message key from current chain key.
        """
        # message_key and next_chain_key derived separately to avoid reuse
        message_key = hashlib.sha256(chain_key + b"msg").digest()
        next_chain_key = hashlib.sha256(chain_key + b"chain" + position.to_bytes(4, "big")).digest()
        return next_chain_key, message_key
    
    def ratchet_encrypt(self, ratchet_state: Dict[str, str], message: str) -> Tuple[Dict[str, str], Dict]:
        """
        Encrypt message using a symmetric ratchet state.
        
        Args:
            ratchet_state: dictionary with 'chain_key' (hex) and 'position' (int)
            message: plaintext
            
        Returns:
            (updated_ratchet_state, encrypted_dict)
        """
        position = int(ratchet_state.get("position", 0)) + 1
        chain_key = bytes.fromhex(ratchet_state["chain_key"])
        
        next_chain_key, message_key = self._ratchet_step(chain_key, position)
        
        # AES-256-GCM with message-specific key
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
        
        auth_tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        new_state = {
            "root_key": ratchet_state["root_key"],
            "chain_key": next_chain_key.hex(),
            "position": position,
        }
        
        return new_state, {
            "nonce": nonce.hex(),
            "ciphertext": encrypted_data.hex(),
            "auth_tag": auth_tag.hex(),
        }
    
    def ratchet_decrypt(self, ratchet_state: Dict[str, str], encrypted_data: Dict) -> Tuple[Dict[str, str], Optional[str]]:
        """
        Decrypt message using a symmetric ratchet state.
        
        Uses the same derivation as ratchet_encrypt.
        """
        try:
            position = int(ratchet_state.get("position", 0)) + 1
            chain_key = bytes.fromhex(ratchet_state["chain_key"])
            
            next_chain_key, message_key = self._ratchet_step(chain_key, position)
            
            nonce = bytes.fromhex(encrypted_data["nonce"])
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            auth_tag = bytes.fromhex(encrypted_data["auth_tag"])
            full_ciphertext = ciphertext + auth_tag
            
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, None)
            
            new_state = {
                "root_key": ratchet_state["root_key"],
                "chain_key": next_chain_key.hex(),
                "position": position,
            }
            
            return new_state, plaintext.decode("utf-8")
        except Exception:
            return ratchet_state, None
    
    # ------------------------------------------------------------------
    # Bonus Feature 2: Group Messaging with Shared Keys
    # ------------------------------------------------------------------
    def generate_group_key(self) -> str:
        """
        Generate a random 256-bit symmetric key for group messaging.
        
        Returns:
            Group key as hex string.
        """
        key = secrets.token_bytes(32)
        return key.hex()
    
    def encrypt_group_message(self, group_key_hex: str, message: str) -> Dict:
        """
        Encrypt a message with a shared group key.
        
        Args:
            group_key_hex: 32-byte AES key in hex
            message: plaintext message
        """
        key = bytes.fromhex(group_key_hex)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
        
        auth_tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        return {
            "nonce": nonce.hex(),
            "ciphertext": encrypted_data.hex(),
            "auth_tag": auth_tag.hex(),
        }
    
    def decrypt_group_message(self, encrypted_data: Dict, group_key_hex: str) -> Optional[str]:
        """
        Decrypt a message with a shared group key.
        """
        try:
            key = bytes.fromhex(group_key_hex)
            nonce = bytes.fromhex(encrypted_data["nonce"])
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            auth_tag = bytes.fromhex(encrypted_data["auth_tag"])
            full_ciphertext = ciphertext + auth_tag
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception:
            return None

