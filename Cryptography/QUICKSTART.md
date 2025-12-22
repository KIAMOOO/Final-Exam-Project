# Quick Start Guide

## Getting Started in 5 Minutes

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**
   ```bash
   python src/main.py
   ```

3. **Open your browser**
   Navigate to: `http://localhost:5000`

4. **Create an account**
   - Click "Sign Up"
   - Choose a username and strong password
   - Password must contain: uppercase, lowercase, digit, and special character

5. **Login**
   - Use your credentials to login
   - Optionally setup TOTP for two-factor authentication

## Features Overview

### 🔐 Authentication
- **Registration**: Secure password hashing with Argon2id
- **Login**: Session-based authentication with rate limiting
- **TOTP**: Two-factor authentication with QR codes and keys
- **Account Lockout**: Protection against brute force attacks

### 💬 Secure Messaging
1. Generate a key pair (Dashboard → Messaging)
2. Share your public key with recipient
3. Encrypt and send messages
4. Recipient decrypts using their private key

### 📁 File Encryption
1. Upload a file
2. Enter encryption password
3. Download encrypted file
4. Decrypt using the same password

### ⛓️ Audit Trail
- View all security events logged to blockchain
- Immutable record of:
  - Login attempts
  - File operations
  - Message exchanges
  - Custom events

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

# View audit trail
chain = vault.get_audit_trail()
```

## Security Best Practices

1. **Use strong passwords** - Mix of uppercase, lowercase, numbers, and symbols
2. **Enable TOTP** - Two-factor authentication adds an extra security layer
3. **Keep private keys secure** - Never share your private keys
4. **Use unique passwords** - Different password for file encryption vs account
5. **Regular backups** - Backup encrypted files and backup codes

## Need Help?

- Check `README.md` for detailed documentation
- Review `INSTALL.md` for installation troubleshooting
- Examine code comments for implementation details


