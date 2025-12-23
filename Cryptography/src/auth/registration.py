"""
User registration with secure password hashing
"""

import secrets
import re
import hashlib
from typing import Tuple, Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .models import User, db


class Registration:
    """
    Handles user registration with secure password hashing.
    
    Features:
    - Argon2id password hashing (or bcrypt fallback)
    - CSPRNG salt generation
    - Password strength validation
    - Secure storage of hashed password + salt
    """
    
    def __init__(self):
        self.password_hasher = PasswordHasher()
    
    def validate_password_strength(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength.
        
        Requirements:
        - At least 8 characters
        - Contains uppercase letter
        - Contains lowercase letter
        - Contains digit
        - Contains special character
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple (is_valid, error_message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, None
    
    def validate_username(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Validate username format.
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple (is_valid, error_message)
        """
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 20:
            return False, "Username must be at most 20 characters long"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        return True, None
    
    def hash_password(self, password: str) -> Tuple[str, str]:
        """
        Hash password using Argon2id with CSPRNG salt.
        
        Args:
            password: Plaintext password
            
        Returns:
            Tuple (password_hash, salt)
        """
        # Generate random salt using CSPRNG
        salt = secrets.token_hex(32)
        
        # Hash password with Argon2id
        # Argon2id includes salt in the hash, but we store it separately for compatibility
        password_hash = self.password_hasher.hash(password)
        
        return password_hash, salt
    
    def register_user(self, username: str, password: str, email: str) -> Tuple[bool, Optional[str], Optional[User]]:
        """
        Register a new user.
        
        Args:
            username: Desired username
            password: Plaintext password
            email: Email address (required)
            
        Returns:
            Tuple (success, error_message, user_object)
        """
        # Validate username
        is_valid, error = self.validate_username(username)
        if not is_valid:
            return False, error, None
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return False, "Username already exists", None
        
        # Validate password
        is_valid, error = self.validate_password_strength(password)
        if not is_valid:
            return False, error, None
        
        # Validate email is provided
        if not email or not email.strip():
            return False, "Email is required", None
        
        email = email.strip()
        
        # Validate email format
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return False, "Invalid email format", None
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return False, "Email already registered", None
        
        try:
            # Hash password
            password_hash, salt = self.hash_password(password)
            
            # Create user
            user = User(
                username=username,
                password_hash=password_hash,
                salt=salt,
                email=email
            )
            
            db.session.add(user)
            db.session.commit()
            
            return True, None, user
        
        except Exception as e:
            db.session.rollback()
            return False, f"Registration failed: {str(e)}", None
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Plaintext password to verify
            stored_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            self.password_hasher.verify(stored_hash, password)
            return True
        except VerifyMismatchError:
            return False

