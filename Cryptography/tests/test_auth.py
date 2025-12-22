"""
Tests for authentication module
"""

import pytest
from src.auth.registration import Registration
from src.auth.login import Login
from src.auth.totp import TOTPManager
from src.auth.models import User, db
from src.web.app import app


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()


class TestRegistration:
    """Test user registration"""
    
    def test_validate_password_strength(self):
        """Test password strength validation"""
        reg = Registration()
        
        # Weak passwords
        assert not reg.validate_password_strength("short")[0]
        assert not reg.validate_password_strength("nouppercase123!")[0]
        assert not reg.validate_password_strength("NOLOWERCASE123!")[0]
        assert not reg.validate_password_strength("NoDigits!")[0]
        assert not reg.validate_password_strength("NoSpecial123")[0]
        
        # Strong password
        assert reg.validate_password_strength("StrongPass123!")[0]
    
    def test_validate_username(self):
        """Test username validation"""
        reg = Registration()
        
        assert not reg.validate_username("ab")[0]  # Too short
        assert not reg.validate_username("a" * 21)[0]  # Too long
        assert not reg.validate_username("user-name")[0]  # Invalid char
        assert reg.validate_username("valid_user123")[0]
    
    def test_hash_password(self):
        """Test password hashing"""
        reg = Registration()
        password = "TestPassword123!"
        hash1, salt1 = reg.hash_password(password)
        hash2, salt2 = reg.hash_password(password)
        
        # Hashes should be different (different salts)
        assert hash1 != hash2
        assert salt1 != salt2


class TestLogin:
    """Test user login"""
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        login = Login()
        
        # Should allow first attempts
        allowed, _ = login._check_rate_limit("testuser")
        assert allowed
        
        # Should allow multiple attempts within limit
        for _ in range(4):
            allowed, _ = login._check_rate_limit("testuser")
            assert allowed


class TestTOTP:
    """Test TOTP functionality"""
    
    def test_generate_secret(self):
        """Test secret generation"""
        totp = TOTPManager()
        secret = totp.generate_secret()
        assert len(secret) > 0
        assert secret != totp.generate_secret()  # Should be different
    
    def test_generate_backup_codes(self):
        """Test backup code generation"""
        totp = TOTPManager()
        codes = totp.generate_backup_codes()
        assert len(codes) == 10
        assert len(set(codes)) == 10  # All unique

