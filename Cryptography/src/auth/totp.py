"""
TOTP (Time-based One-Time Password) implementation
"""

import secrets
import json
import pyotp
import qrcode
from io import BytesIO
import base64
from typing import Tuple, List, Optional
from .models import User, db


class TOTPManager:
    """
    Manages TOTP-based multi-factor authentication.
    
    Features:
    - TOTP secret generation
    - QR code generation for authenticator apps
    - Backup codes with secure storage
    - TOTP verification with time window tolerance
    """
    
    def __init__(self):
        self.backup_code_count = 10
        self.time_window = 1  # Allow 1 time step tolerance (±30 seconds)
    
    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32-encoded secret
        """
        return pyotp.random_base32()
    
    def generate_backup_codes(self) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(self.backup_code_count):
            code = secrets.token_hex(4).upper()  # 8-character hex code
            codes.append(code)
        return codes
    
    def get_provisioning_uri(self, username: str, secret: str, issuer: str = "CryptoVault") -> str:
        """
        Get provisioning URI for QR code generation.
        
        Args:
            username: Username
            secret: TOTP secret
            issuer: Service name
            
        Returns:
            otpauth:// URI
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    def generate_qr_code(self, username: str, secret: str, issuer: str = "CryptoVault") -> str:
        """
        Generate QR code image as base64 string.
        
        Args:
            username: Username
            secret: TOTP secret
            issuer: Service name
            
        Returns:
            Base64-encoded PNG image
        """
        uri = self.get_provisioning_uri(username, secret, issuer)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_base64}"
    
    def setup_totp(self, user: User) -> Tuple[str, List[str], str]:
        """
        Setup TOTP for a user.
        
        Args:
            user: User object
            
        Returns:
            Tuple (secret, backup_codes, qr_code_base64)
        """
        secret = self.generate_secret()
        backup_codes = self.generate_backup_codes()
        
        # Store secret and backup codes
        user.totp_secret = secret
        user.backup_codes = json.dumps(backup_codes)
        db.session.commit()
        
        # Generate QR code
        qr_code = self.generate_qr_code(user.username, secret)
        
        return secret, backup_codes, qr_code
    
    def verify_totp(self, user: User, code: str) -> bool:
        """
        Verify TOTP code for user.
        
        Args:
            user: User object
            code: TOTP code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        if not user.totp_secret:
            return False
        
        totp = pyotp.TOTP(user.totp_secret)
        
        # Verify with time window tolerance
        return totp.verify(code, valid_window=self.time_window)
    
    def verify_backup_code(self, user: User, code: str) -> bool:
        """
        Verify backup code and remove it if valid.
        
        Args:
            user: User object
            code: Backup code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        if not user.backup_codes:
            return False
        
        backup_codes = json.loads(user.backup_codes)
        code_upper = code.upper()
        
        if code_upper in backup_codes:
            # Remove used backup code
            backup_codes.remove(code_upper)
            user.backup_codes = json.dumps(backup_codes) if backup_codes else None
            db.session.commit()
            return True
        
        return False
    
    def enable_totp(self, user: User):
        """Enable TOTP for user"""
        user.totp_enabled = True
        db.session.commit()
    
    def disable_totp(self, user: User):
        """Disable TOTP for user"""
        user.totp_enabled = False
        user.totp_secret = None
        user.backup_codes = None
        db.session.commit()

