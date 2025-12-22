"""
User login with session management and rate limiting
"""

import secrets
import hmac
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple
from .models import User, Session, db
from .registration import Registration


class Login:
    """
    Handles user login with security features.
    
    Features:
    - Constant-time password verification
    - Rate limiting protection
    - HMAC-SHA256 session token generation
    - Secure session storage
    """
    
    def __init__(self):
        self.registration = Registration()
        self.session_secret = secrets.token_bytes(32)  # In production, load from config
        self.rate_limit_window = 300  # 5 minutes
        self.rate_limit_attempts = 5
        self.login_attempts = {}  # In production, use Redis or similar
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings match, False otherwise
        """
        return hmac.compare_digest(a.encode(), b.encode())
    
    def _check_rate_limit(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if user has exceeded rate limit.
        
        Args:
            username: Username to check
            
        Returns:
            Tuple (allowed, error_message)
        """
        now = time.time()
        key = f"login:{username}"
        
        if key in self.login_attempts:
            attempts, first_attempt = self.login_attempts[key]
            
            # Reset if window expired
            if now - first_attempt > self.rate_limit_window:
                self.login_attempts[key] = (1, now)
                return True, None
            
            # Check if exceeded limit
            if attempts >= self.rate_limit_attempts:
                remaining = int(self.rate_limit_window - (now - first_attempt))
                return False, f"Too many login attempts. Try again in {remaining} seconds."
            
            # Increment attempts
            self.login_attempts[key] = (attempts + 1, first_attempt)
        else:
            self.login_attempts[key] = (1, now)
        
        return True, None
    
    def _reset_rate_limit(self, username: str):
        """Reset rate limit for user after successful login"""
        key = f"login:{username}"
        if key in self.login_attempts:
            del self.login_attempts[key]
    
    def _generate_session_token(self, user_id: int, username: str) -> str:
        """
        Generate HMAC-SHA256 session token.
        
        Args:
            user_id: User ID
            username: Username
            
        Returns:
            Session token
        """
        timestamp = str(int(time.time()))
        message = f"{user_id}:{username}:{timestamp}"
        token = hmac.new(
            self.session_secret,
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{user_id}:{timestamp}:{token}"
    
    def login(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticate user and create session.
        
        Args:
            username: Username
            password: Plaintext password
            ip_address: Optional IP address for logging
            
        Returns:
            Tuple (success, error_message, session_token)
        """
        # Check rate limit
        allowed, error = self._check_rate_limit(username)
        if not allowed:
            return False, error, None
        
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            # Use constant-time comparison even for non-existent users
            self._constant_time_compare(password, "dummy")
            return False, "Invalid username or password", None
        
        # Check if account is locked
        if user.is_locked():
            return False, "Account is locked due to too many failed attempts", None
        
        # Verify password (constant-time)
        if not self.registration.verify_password(password, user.password_hash):
            user.increment_failed_attempts()
            return False, "Invalid username or password", None
        
        # Reset failed attempts on successful login
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        # Reset rate limit
        self._reset_rate_limit(username)
        
        # Create session
        session = Session.create_session(user.id, ip_address)
        
        return True, None, session.token
    
    def verify_session(self, token: str) -> Optional[User]:
        """
        Verify session token and return user.
        
        Args:
            token: Session token
            
        Returns:
            User object if valid, None otherwise
        """
        session = Session.query.filter_by(token=token).first()
        
        if not session or not session.is_valid():
            return None
        
        return session.user
    
    def logout(self, token: str) -> bool:
        """
        Invalidate session token.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            True if successful, False otherwise
        """
        session = Session.query.filter_by(token=token).first()
        if session:
            db.session.delete(session)
            db.session.commit()
            return True
        return False

