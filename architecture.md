## CryptoVault Architecture

### 1. High-Level System Overview

CryptoVault is a modular cryptographic security suite exposed through:
- **Core library** (`src/`) – Python API and cryptographic primitives.
- **Web app** (`src/web/app.py`) – Flask UI for end users.
- **Integration facade** (`src/cryptovault.py`) – Ties all modules together and connects them to the blockchain audit ledger.

All security‑relevant operations (auth, messaging, files) are logged to the **Blockchain Audit Ledger** for integrity and non‑repudiation.

### 2. Module Decomposition

- **Authentication Module (`src/auth/`)**
  - `registration.py` – Validates usernames/passwords, hashes passwords with Argon2id, stores users.
  - `login.py` – Verifies passwords, enforces rate limiting and account lockout, manages sessions.
  - `totp.py` – TOTP secrets, QR codes, backup codes, and verification / enabling.
  - `models.py` – SQLAlchemy models for `User`, `Session`, `PasswordResetToken`.
  - `email_service.py` / `smtp_email_service.py` – Password reset email sending via Mailjet/SMTP.

- **Messaging Module (`src/messaging/`)**
  - `messaging.py` – ECDH (P‑256) key exchange, HKDF key derivation, AES‑256‑GCM encryption, ECDSA signatures, simple ratchet (PFS) and group messaging helpers.

- **File Encryption Module (`src/files/`)**
  - `file_encryption.py` – PBKDF2 master key derivation, FEK generation, AES‑256‑GCM streaming file encryption, SHA‑256 + HMAC integrity/authenticity checks.

- **Blockchain Module (`src/blockchain/`)**
  - `blockchain.py` – `Transaction`, `Block`, and `BlockchainModule` with PoW, difficulty, block/chain verification, and audit logging helpers.
  - `merkle.py` – Merkle tree implementation, including proof generation and verification.

- **Core Crypto (`src/crypto/`)**
  - `classical.py` – Caesar and Vigenère ciphers plus frequency analysis and Kasiski examination.
  - `sha256.py` – Educational SHA‑256 implementation.
  - `aes_expansion.py` – AES key expansion (key schedule).
  - `rsa.py` – RSA key generation and modular exponentiation (square‑and‑multiply).

- **Web Layer (`src/web/`)**
  - `app.py` – Flask routes, session handling, and wiring to `CryptoVault`.
  - `templates/` – HTML templates for auth, dashboard, messaging, files, audit, password reset.
  - `static/` – CSS and JavaScript for UI.

- **Integration (`src/cryptovault.py`)**
  - Instantiates `Registration`, `Login`, `TOTPManager`, `MessagingModule`, `FileEncryptionModule`, `BlockchainModule`, and `EmailService`.
  - Exposes high‑level methods: `register`, `login`, `setup_totp`, `encrypt_file`, `decrypt_file`, `send_message`, `receive_message`, password reset helpers, and blockchain access.

### 3. Data and Control Flow

#### 3.1 Authentication + MFA

1. **Registration**
   - Web form → `/register` → `CryptoVault.register()` → `Registration.register_user()`.
   - Password is validated, hashed with Argon2id, and stored in `users` table.
   - An `AUTH_REGISTER` event is logged to the blockchain.

2. **Login**
   - Web form → `/login` → `CryptoVault.login()` → `Login.login()`.
   - Rate limiting and account lockout enforced.
   - On correct password, a `Session` row is created and token stored in Flask `session`.
   - If TOTP is enabled, a valid code (or backup code) is required.
   - Successful/failed attempts are logged as `AUTH_LOGIN` events.

3. **TOTP Setup**
   - Authenticated user calls `/setup_totp` → `CryptoVault.setup_totp()`.
   - `TOTPManager` generates secret + backup codes and QR image.
   - User confirms first code via `/confirm_totp`; `TOTPManager.enable_totp()` flips `totp_enabled=True`.

4. **Password Reset**
   - `/forgot_password` calls `CryptoVault.request_password_reset()` to generate and store a one‑time token.
   - Email service sends a reset link; `/reset_password/<token>` calls `CryptoVault.reset_password()` after validating token and new password.
   - Events `AUTH_PASSWORD_RESET_REQUEST` and `AUTH_PASSWORD_RESET` are logged.

#### 3.2 Secure Messaging

1. Each user generates an ECDH keypair via `/api/generate_keypair` (uses `MessagingModule.generate_keypair()`).
2. To send a message:
   - `/api/send_message` → `CryptoVault.send_message()`.
   - `MessagingModule.encrypt_message()`:
     - Generates an ephemeral ECDH keypair.
     - Does ECDH with recipient’s public key.
     - Uses HKDF to derive a 256‑bit AES key.
     - Encrypts with AES‑256‑GCM (fresh nonce).
     - Signs ciphertext with sender’s private key (ECDSA).
   - `MESSAGE_SEND` event with SHA‑256 of plaintext is logged to blockchain.
3. To receive:
   - `/api/receive_message` → `CryptoVault.receive_message()`.
   - Verifies signature, derives the same AES key, and decrypts.
   - Logs `MESSAGE_RECEIVE` event.

#### 3.3 File Encryption

1. User uploads file and password via `/api/encrypt_file`.
2. `CryptoVault.encrypt_file()` delegates to `FileEncryptionModule.encrypt_file()`:
   - Computes SHA‑256 of original file.
   - Derives master key from password with PBKDF2 (≥100k iterations, fresh salt).
   - Generates random FEK and encrypts it with master key (AES‑GCM).
   - Encrypts file in streaming fashion with FEK using AES‑256‑GCM and incrementing nonce.
   - Computes HMAC over the encrypted file hash.
   - Writes metadata header + encrypted chunks to disk.
   - Logs a `FILE_ENCRYPT` event with original and encrypted hashes.
3. Decryption via `/api/decrypt_file`:
   - Reads metadata, re‑derives master key from password + stored salt.
   - Decrypts FEK, then file chunks.
   - Verifies decrypted file hash matches original hash; on mismatch, file is deleted and error returned.
   - Logs `FILE_DECRYPT` event.

#### 3.4 Blockchain Audit Ledger

1. Any call to `CryptoVault.log_event()` creates a `Transaction` and adds it to `BlockchainModule.pending_transactions`.
2. When at least one transaction is pending, `BlockchainModule.create_block()`:
   - Builds Merkle tree over tx hashes and sets `merkle_root`.
   - Uses PoW to find a nonce such that `hash < target`.
   - Adds the block to the chain and clears pending transactions.
3. `/audit` + `/api/audit_trail` visualize all blocks and events; `/api/verify_chain` runs full chain verification.

### 4. Technology Stack & Key Libraries

- **Language**: Python 3.8+
- **Web Framework**: Flask
- **Database**: SQLite via SQLAlchemy
- **Crypto libraries**:
  - `cryptography` (AES‑GCM, ECDH, ECDSA, HKDF, PBKDF2)
  - `argon2-cffi` (Argon2id password hashing)
  - `pyotp` (TOTP)
  - `qrcode` (QR code images)
  - From‑scratch algorithms in `src/crypto/` for educational purposes.

### 5. Deployment / Runtime Notes

- Default entrypoint: `python src/main.py` (runs Flask on `http://localhost:5000`).
- DB file `cryptovault.db` lives under `instance/` or root depending on configuration.
- Sensitive configuration (Mailjet/SMTP keys, FROM_EMAIL, etc.) is loaded from environment variables (`.env`).


