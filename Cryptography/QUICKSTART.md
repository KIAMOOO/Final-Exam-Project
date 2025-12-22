# Quick Start Guide

## Getting Started in 5 Minutes

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment variables**
   ```bash
   # Copy and edit the .env file with your email service credentials
   cp .env.example .env
   ```

3. **Run the application**
   ```bash
   python src/main.py
   ```

4. **Open your browser**
   Navigate to: `http://localhost:5000`

5. **Create an account**
   - Click "Sign Up"
   - Choose a username and strong password
   - Password must contain: uppercase, lowercase, digit, and special character

## Features Overview

### 🔐 Authentication
- **Registration**: Secure password hashing with Argon2id
- **Login**: Session-based authentication with rate limiting
- **TOTP**: Two-factor authentication with QR codes and backup keys
- **Account Lockout**: Protection against brute force attacks
- **Password Reset**: Secure email-based password recovery

### 💬 Secure Messaging
1. Generate a key pair (Dashboard → Messaging)
2. Share your public key with recipient
3. Encrypt and send messages using ECDH and AES-GCM
4. Recipient decrypts using their private key

### 📁 File Encryption
1. Upload a file (Dashboard → Files)
2. Enter encryption password
3. Download encrypted file with HMAC authentication
4. Decrypt using the same password (AES-256-GCM)

### ⛓️ Blockchain Audit Trail
- View all security events logged to blockchain
- Immutable record of:
  - Login attempts
  - File operations
  - Message exchanges
  - Password reset events
  - Custom audit events

### 🔒 Cryptographic Algorithms
- **RSA**: For key generation and digital signatures
- **AES-256-GCM**: For file and message encryption
- **SHA-256**: For hashing and integrity verification
- **ECDH**: For secure key exchange in messaging
- **Argon2id**: For password hashing

## Example Usage

### Python API

```python
from src.cryptovault import CryptoVault

# Initialize
vault = CryptoVault()

# Register
vault.register("alice", "SecurePass123!", "alice@example.com")

# Login
success, error, token = vault.login("alice", "SecurePass123!")

# Encrypt file
vault.encrypt_file("document.pdf", "file_password", "alice")

# Decrypt file
vault.decrypt_file("document.pdf.encrypted", "file_password")

# View audit trail
chain = vault.get_audit_trail()
```

## Security Best Practices

1. **Use strong passwords** - Mix of uppercase, lowercase, numbers, and symbols
2. **Enable TOTP** - Two-factor authentication adds an extra security layer
3. **Keep private keys secure** - Never share your private/backup keys
4. **Use unique passwords** - Different passwords for account vs file encryption
5. **Verify recipients** - Confirm public keys before sending sensitive messages
6. **Regular backups** - Backup encryption keys and backup codes
7. **Check the chain** - Review the blockchain audit trail for suspicious activity

## Need Help?

- Check `README.md` for detailed documentation
- Review `INSTALL.md` for installation troubleshooting
- Examine code comments for implementation details
- Look at `tests/` directory for usage examples
│   └── ...
├── .env                                # ← Configuration
├── test_smtp.py                        # ← Test script
├── email_service_factory.py            # ← Service selector
└── ...
```

---

## Features

✅ Password reset via email
✅ SMTP with TLS encryption
✅ Secure token generation (32-byte)
✅ 1-hour token expiry
✅ One-time use tokens
✅ Argon2id password hashing
✅ HTML + text emails

---

## API Endpoints

### Password Reset Request
```bash
curl -X POST http://localhost:5000/forgot_password \
  -H "Content-Type: application/json" \
  -d '{"identifier": "username_or_email@example.com"}'
```

### Reset Password
```bash
curl -X POST http://localhost:5000/reset_password/TOKEN \
  -H "Content-Type: application/json" \
  -d '{
    "password": "new_password",
    "confirm_password": "new_password"
  }'
```

---

## Next Steps

- ✅ Review `README.md` for full documentation
- ✅ Check `src/auth/smtp_email_service.py` for code details
- ✅ Review `test_smtp.py` for testing examples

Done! Ready to use. 🎉
