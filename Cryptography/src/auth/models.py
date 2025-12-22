"""
Database models for authentication
"""

from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import secrets

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication"""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, nullable=True)  # JSON array
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until
    
    def lock_account(self, minutes: int = 30):
        """Lock account for specified minutes"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.failed_attempts = 0
        db.session.commit()
    
    def unlock_account(self):
        """Unlock account"""
        self.locked_until = None
        self.failed_attempts = 0
        db.session.commit()
    
    def increment_failed_attempts(self):
        """Increment failed login attempts"""
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.lock_account()
        db.session.commit()


class Session(db.Model):
    """Session model for authentication tokens"""
    
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    ip_address_hash = db.Column(db.String(64), nullable=True)
    
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))
    
    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return datetime.utcnow() < self.expires_at
    
    @staticmethod
    def create_session(user_id: int, ip_address: str = None) -> 'Session':
        """Create a new session"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Hash IP address for privacy
        ip_hash = None
        if ip_address:
            import hashlib
            ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
        
        session = Session(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address_hash=ip_hash
        )
        db.session.add(session)
        db.session.commit()
        return session


class PasswordResetToken(db.Model):
    """Password reset token model"""
    
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))
    
    def is_valid(self) -> bool:
        """Check if token is valid"""
        return not self.used and datetime.utcnow() < self.expires_at

