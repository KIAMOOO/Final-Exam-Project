"""
Main CryptoVault integration class
"""

import hashlib
from typing import Optional, Tuple
from src.auth.registration import Registration
from src.auth.login import Login
from src.auth.totp import TOTPManager
from src.auth.models import User, db
from src.messaging import MessagingModule
from src.files import FileEncryptionModule
from src.blockchain import BlockchainModule, Transaction


class CryptoVault:
    """
    Main CryptoVault suite integrating all modules.
    
    Provides unified interface for:
    - Authentication with MFA
    - Secure messaging
    - File encryption
    - Blockchain audit logging
    """
    
    def __init__(self, difficulty: int = 4):
        """
        Initialize CryptoVault suite.
        
        Args:
            difficulty: Blockchain PoW difficulty
        """
        self.auth_registration = Registration()
        self.auth_login = Login()
        self.totp_manager = TOTPManager()
        self.messaging = MessagingModule()
        self.files = FileEncryptionModule()
        self.ledger = BlockchainModule(difficulty=difficulty)
    
    def register(self, username: str, password: str, email: str = None) -> Tuple[bool, Optional[str]]:
        """
        Register a new user.
        
        Args:
            username: Desired username
            password: Password
            email: Optional email
            
        Returns:
            Tuple (success, error_message)
        """
        success, error, user = self.auth_registration.register_user(username, password, email)
        
        if success:
            # Log registration event
            self.log_event('AUTH_REGISTER', {
                'user_hash': self._hash_username(username),
                'timestamp': self._get_timestamp()
            })
        
        return success, error
    
    def login(self, username: str, password: str, totp_code: str = None, 
              ip_address: str = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Login user with optional TOTP.
        
        Args:
            username: Username
            password: Password
            totp_code: Optional TOTP code
            ip_address: Optional IP address
            
        Returns:
            Tuple (success, error_message, session_token)
        """
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            self.log_event('AUTH_LOGIN', {
                'user_hash': self._hash_username(username),
                'timestamp': self._get_timestamp(),
                'success': False,
                'ip_hash': self._hash_ip(ip_address) if ip_address else None
            })
            return False, "Invalid username or password", None
        
        # Login
        success, error, token = self.auth_login.login(username, password, ip_address)
        
        if not success:
            self.log_event('AUTH_LOGIN', {
                'user_hash': self._hash_username(username),
                'timestamp': self._get_timestamp(),
                'success': False,
                'ip_hash': self._hash_ip(ip_address) if ip_address else None
            })
            return False, error, None
        
        # Verify TOTP if enabled
        if user.totp_enabled:
            if not totp_code:
                return False, "TOTP code required", None
            
            if not self.totp_manager.verify_totp(user, totp_code):
                # Check backup code
                if not self.totp_manager.verify_backup_code(user, totp_code):
                    self.log_event('AUTH_LOGIN', {
                        'user_hash': self._hash_username(username),
                        'timestamp': self._get_timestamp(),
                        'success': False,
                        'reason': 'invalid_totp',
                        'ip_hash': self._hash_ip(ip_address) if ip_address else None
                    })
                    return False, "Invalid TOTP code", None
        
        # Log successful login
        self.log_event('AUTH_LOGIN', {
            'user_hash': self._hash_username(username),
            'timestamp': self._get_timestamp(),
            'success': True,
            'ip_hash': self._hash_ip(ip_address) if ip_address else None
        })
        
        return True, None, token
    
    def setup_totp(self, username: str) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Setup TOTP for user.
        
        Args:
            username: Username
            
        Returns:
            Tuple (success, error_message, totp_data)
        """
        user = User.query.filter_by(username=username).first()
        if not user:
            return False, "User not found", None
        
        secret, backup_codes, qr_code = self.totp_manager.setup_totp(user)
        self.totp_manager.enable_totp(user)
        
        return True, None, {
            'secret': secret,
            'backup_codes': backup_codes,
            'qr_code': qr_code
        }
    
    def encrypt_file(self, file_path: str, password: str, username: str, 
                    output_path: str = None) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Encrypt file and log to blockchain.
        
        Args:
            file_path: Path to file
            password: Encryption password
            username: Username for logging
            output_path: Optional output path
            
        Returns:
            Tuple (success, error_message, encryption_metadata)
        """
        try:
            metadata = self.files.encrypt_file(file_path, password, output_path)
            
            # Log to blockchain
            self.log_event('FILE_ENCRYPT', {
                'file_hash': metadata['file_hash'],
                'user_hash': self._hash_username(username),
                'timestamp': self._get_timestamp(),
                'encrypted_hash': metadata['encrypted_hash']
            })
            
            return True, None, metadata
        
        except Exception as e:
            return False, str(e), None
    
    def decrypt_file(self, encrypted_file_path: str, password: str, 
                    username: str, output_path: str = None) -> Tuple[bool, Optional[str]]:
        """
        Decrypt file and log to blockchain.
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Decryption password
            username: Username for logging
            output_path: Optional output path
            
        Returns:
            Tuple (success, error_message)
        """
        success, error = self.files.decrypt_file(encrypted_file_path, password, output_path)
        
        # Log to blockchain
        self.log_event('FILE_DECRYPT', {
            'file_hash': self.files.compute_file_hash(encrypted_file_path),
            'user_hash': self._hash_username(username),
            'timestamp': self._get_timestamp(),
            'success': success
        })
        
        return success, error
    
    def send_message(self, recipient_public_key: str, message: str, 
                    sender_private_key: str) -> dict:
        """
        Send encrypted message.
        
        Args:
            recipient_public_key: Recipient's public key (PEM)
            message: Message to send
            sender_private_key: Sender's private key (PEM)
            
        Returns:
            Encrypted message dictionary
        """
        # Normalize PEM strings to avoid deserialization errors from extra whitespace/newlines
        recipient_public_key = recipient_public_key.strip()
        sender_private_key = sender_private_key.strip()

        sender_key = self.messaging.deserialize_private_key(sender_private_key)
        encrypted = self.messaging.encrypt_message(
            recipient_public_key.encode(),
            message,
            sender_key
        )
        
        # Log to blockchain
        self.log_event('MESSAGE_SEND', {
            'message_hash': hashlib.sha256(message.encode()).hexdigest(),
            'timestamp': self._get_timestamp()
        })
        
        return encrypted
    
    def receive_message(self, encrypted_data: dict, recipient_private_key: str,
                       sender_public_key: str) -> Optional[str]:
        """
        Receive and decrypt message.
        
        Args:
            encrypted_data: Encrypted message dictionary
            recipient_private_key: Recipient's private key (PEM)
            sender_public_key: Sender's public key (PEM)
            
        Returns:
            Decrypted message, or None if verification fails
        """
        # Normalize PEM strings to avoid deserialization errors from extra whitespace/newlines
        recipient_private_key = recipient_private_key.strip()
        sender_public_key = sender_public_key.strip()

        recipient_key = self.messaging.deserialize_private_key(recipient_private_key)
        message = self.messaging.decrypt_message(
            encrypted_data,
            recipient_key,
            sender_public_key.encode()
        )
        
        if message:
            # Log to blockchain
            self.log_event('MESSAGE_RECEIVE', {
                'message_hash': hashlib.sha256(message.encode()).hexdigest(),
                'timestamp': self._get_timestamp()
            })
        
        return message
    
    def log_event(self, event_type: str, event_data: dict):
        """
        Log security event to blockchain.
        
        Args:
            event_type: Type of event
            event_data: Event data
        """
        self.ledger.log_event(event_type, event_data)
    
    def get_audit_trail(self) -> list:
        """
        Get audit trail from blockchain.
        
        Returns:
            List of all blocks
        """
        return self.ledger.get_chain_data()
    
    def _hash_username(self, username: str) -> str:
        """Hash username for privacy"""
        return hashlib.sha256(username.encode()).hexdigest()
    
    def _hash_ip(self, ip_address: str) -> str:
        """Hash IP address for privacy"""
        return hashlib.sha256(ip_address.encode()).hexdigest()
    
    def _get_timestamp(self) -> float:
        """Get current timestamp"""
        import time
        return time.time()

