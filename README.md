# CryptoVault Suite

A comprehensive cryptographic toolkit providing secure messaging, file encryption, authentication, and blockchain-based audit trails.

## Features

### 🔐 Authentication System
- Secure user registration with Argon2id password hashing
- Multi-factor authentication with TOTP
- Session management with HMAC-SHA256 tokens
- Password reset and account lockout protection

### 💬 Secure Messaging
- End-to-end encryption using ECDH key exchange
- AES-256-GCM authenticated encryption
- Digital signatures with ECDSA for non-repudiation
- Perfect Forward Secrecy support

### 📁 File Encryption
- AES-256-GCM encryption for files
- PBKDF2 key derivation with 100,000+ iterations
- SHA-256 + HMAC integrity verification
- Secure file sharing capabilities

### ⛓️ Blockchain Audit Ledger
- Immutable audit trail for all security events
- Merkle tree transaction verification
- Proof of Work consensus mechanism
- Tamper-proof logging

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Web Interface

```bash
python src/main.py
```

Navigate to `http://localhost:5000` in your browser.

### Python API

```python
from src.cryptovault import CryptoVault

vault = CryptoVault()
token = vault.login("username", "password", "totp_code")
```


### Project Structure

```
cryptovault/
├── src/
│   ├── __init__.py
│   ├── main.py                 # Entry point
│   ├── cryptovault.py         # Main integration class
│   ├── auth/                   # Authentication module
│   │   ├── __init__.py
│   │   ├── models.py          # Database models
│   │   ├── registration.py    # User registration
│   │   ├── login.py           # Login & sessions
│   │   └── totp.py            # TOTP implementation
│   ├── messaging/              # Secure messaging
│   │   ├── __init__.py
│   │   └── messaging.py      # ECDH + AES-256-GCM
│   ├── files/                  # File encryption
│   │   ├── __init__.py
│   │   └── file_encryption.py # AES-256-GCM + PBKDF2
│   ├── blockchain/             # Blockchain ledger
│   │   ├── __init__.py
│   │   ├── blockchain.py      # Block & chain logic
│   │   └── merkle.py          # Merkle tree
│   ├── crypto/                 # Core crypto (from scratch)
│   │   ├── __init__.py
│   │   ├── sha256.py          # SHA-256 implementation
│   │   ├── classical.py       # Caesar & Vigenère
│   │   ├── rsa.py             # RSA key generation
│   │   └── aes_expansion.py   # AES key expansion
│   └── web/                    # Web interface
│       ├── __init__.py
│       ├── app.py             # Flask application
│       ├── templates/         # HTML templates
│       └── static/            # CSS & JS
│           ├── css/
│           └── js/
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── test_crypto.py
│   ├── test_auth.py
│   └── test_blockchain.py
├── requirements.txt            # Dependencies
├── setup.py                    # Package setup
├── pytest.ini                  # Pytest configuration
├── .gitignore
└── README.md
```


## Security

- All random values use CSPRNG (`secrets` module)
- Constant-time comparisons for sensitive operations
- No hardcoded keys or credentials
- Comprehensive input validation

## Testing

```bash
pytest tests/ --cov=src --cov-report=html
```

## Core Cryptographic Implementations

This project includes implementations from scratch of:

1. **SHA-256 Hash Function** - Simplified implementation demonstrating the core algorithm
2. **Caesar Cipher** - Classical cipher with frequency analysis breaker
3. **Vigenère Cipher** - Polyalphabetic cipher with Kasiski examination
4. **RSA Key Generation** - Prime generation with Miller-Rabin test and modular exponentiation
5. **AES Key Expansion** - Key scheduling algorithm demonstration

## Module Details

### Authentication Module (`src/auth/`)
- **Registration** (`registration.py`): User registration with password strength validation
- **Login** (`login.py`): Secure login with rate limiting and session management
- **TOTP** (`totp.py`): Time-based One-Time Password implementation with QR codes
- **Models** (`models.py`): Database models for users, sessions, and password reset tokens

### Messaging Module (`src/messaging/`)
- **ECDH Key Exchange**: Elliptic Curve Diffie-Hellman using P-256 curve
- **AES-256-GCM Encryption**: Authenticated encryption with unique nonces
- **ECDSA Signatures**: Digital signatures for message authenticity and non-repudiation

### File Encryption Module (`src/files/`)
- **AES-256-GCM**: Streaming encryption for large files
- **PBKDF2**: Key derivation with 100,000+ iterations
- **Integrity Verification**: SHA-256 hashing and HMAC-SHA256 authentication

### Blockchain Module (`src/blockchain/`)
- **Block Structure**: Previous hash, Merkle root, timestamp, nonce
- **Merkle Tree**: Efficient transaction verification with proofs
- **Proof of Work**: Adjustable difficulty mining algorithm
- **Chain Verification**: Integrity checking for entire blockchain

## API Examples

### Authentication

```python
from src.cryptovault import CryptoVault

vault = CryptoVault()

# Register user
success, error = vault.register("username", "StrongPass123!", "email@example.com")

# Login
success, error, token = vault.login("username", "StrongPass123!", totp_code="123456")

# Setup TOTP
success, error, totp_data = vault.setup_totp("username")
# totp_data contains: secret, backup_codes, qr_code
```

### File Encryption

```python
# Encrypt file
success, error, metadata = vault.encrypt_file(
    "document.pdf",
    "encryption_password",
    "username"
)

# Decrypt file
success, error = vault.decrypt_file(
    "encrypted_files/document.pdf.encrypted",
    "encryption_password",
    "username"
)
```

### Secure Messaging

```python
from src.messaging import MessagingModule

messaging = MessagingModule()

# Generate key pair
private_key, public_key = messaging.generate_keypair()
private_pem, public_pem = messaging.serialize_keypair(private_key)

# Send encrypted message
encrypted = vault.send_message(
    recipient_public_key=recipient_pubkey_pem,
    message="Hello, secure world!",
    sender_private_key=sender_privkey_pem
)

# Receive and decrypt
message = vault.receive_message(
    encrypted_data=encrypted,
    recipient_private_key=recipient_privkey_pem,
    sender_public_key=sender_pubkey_pem
)
```

### Audit Trail

```python
# Log custom event
vault.log_event('CUSTOM_EVENT', {
    'user_hash': vault._hash_username('username'),
    'action': 'custom_action',
    'timestamp': vault._get_timestamp()
})

# Get audit trail
chain = vault.get_audit_trail()
for block in chain:
    print(f"Block {block['index']}: {len(block['transactions'])} transactions")
```

## Security Features

### Password Security
- Argon2id hashing with CSPRNG salt generation
- Password strength validation (uppercase, lowercase, digit, special char)
- Account lockout after 5 failed attempts (30-minute lockout)

### Session Security
- HMAC-SHA256 session tokens
- Session expiration (24 hours)
- IP address hashing for privacy

### Encryption Security
- AES-256-GCM for authenticated encryption
- Unique nonces per encryption operation
- PBKDF2 with 100,000+ iterations for key derivation
- SHA-256 + HMAC-SHA256 for integrity verification

### Blockchain Security
- Merkle tree for transaction verification
- Proof of Work consensus
- Immutable audit trail
- Chain integrity verification

## Testing

Run all tests with coverage:

```bash
pytest tests/ --cov=src --cov-report=html
```

View coverage report:
```bash
# HTML report will be generated in htmlcov/index.html
open htmlcov/index.html
```

Test individual modules:
```bash
pytest tests/test_crypto.py      # Core crypto tests
pytest tests/test_auth.py        # Authentication tests
pytest tests/test_blockchain.py # Blockchain tests
```

## Development


## License

MIT License

## Contribution

Aidos (Role — Auth & Security Lead): Built authentication (Argon2/TOTP), set secure coding patterns, 
reviewed code for vulns, contributed to messaging glue and tests, wrote security notes/docs.


Adil (Role — Crypto & Messaging Lead): Implemented crypto/messaging flows (ECDH/ECDSA/AES-GCM/HKDF), maintained key management, 
supported file encryption logic, helped with auth integration and testing, added docs.


Arsen (Role — Blockchain & Integration Lead): Built blockchain/Merkle/audit logging, drove file encryption module, 
integrated modules end-to-end, strengthened tests, and produced documentation.




