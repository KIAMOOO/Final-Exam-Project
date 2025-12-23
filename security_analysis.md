## CryptoVault Security Analysis

This document summarizes the threat model, security controls, and known limitations of the CryptoVault Suite.

### 1. Assets

**Primary assets protected:**
- **User credentials**
  - Usernames
  - Passwords (hashed)
  - TOTP secrets and backup codes
- **Cryptographic keys**
  - Messaging keypairs (ECDH/ECDSA)
  - File Encryption Keys (FEKs)
  - Master keys derived from user passwords
- **Confidential data**
  - Message contents
  - Encrypted and decrypted files
- **Audit data**
  - Blockchain ledger (blocks, transactions, Merkle trees)
  - Security‑relevant events (auth, file operations, messaging, password resets)

### 2. Threat Actors

- **External attackers**
  - Attempt password guessing / credential stuffing.
  - Intercept network traffic (MITM).
  - Try to modify stored encrypted files or tamper with the blockchain.
- **Malicious insiders**
  - Authorized users trying to access other users’ data.
  - Attempt to bypass access controls or forge audit logs.
- **Compromised clients**
  - Malware on the user’s machine stealing session tokens or keys.
  - Shoulder‑surfing or keylogging for passwords / TOTP codes.

### 3. Attack Vectors and Mitigations

| Threat / Vector                              | Mitigation                                                                                   |
|---------------------------------------------|----------------------------------------------------------------------------------------------|
| Password brute force / credential stuffing  | Argon2id hashing, password strength validation, rate limiting, account lockout, TOTP option |
| Password database theft                     | Argon2id hashes with CSPRNG salts, no plaintext storage                                      |
| Session hijacking                           | High‑entropy session tokens, expiration, IP hashing for audit, server‑side session invalidation |
| MITM on login / messages                    | Intended deployment behind HTTPS (TLS), ECDH key exchange + ECDSA signatures for messages   |
| File tampering (on disk)                    | SHA‑256 integrity checks; decryption fails on hash mismatch; HMAC over encrypted file hash  |
| Message forgery / spoofing                  | ECDSA signatures on ciphertext verified before decryption                                   |
| Replay of old encrypted messages            | Fresh nonces per message (AES‑GCM); timestamps logged on blockchain for audit detection     |
| Tampering with audit logs                   | Blockchain ledger with previous block hash + Merkle root and PoW; full chain verification   |
| Weak / predictable randomness               | All security‑critical randomness uses `secrets` or `os.urandom`                             |
| SQL injection / basic input abuse           | SQLAlchemy ORM, server‑side input validation on critical fields                             |

### 4. Security Mechanisms (By Module)

#### 4.1 Authentication

- **Password security**
  - Argon2id hashing using `argon2-cffi`.
  - Additional CSPRNG salt stored separately per user.
  - Strong password policy enforced in code.
- **Login protection**
  - In‑memory rate limiting (max attempts per window).
  - Account lockout after repeated failures (`User.is_locked()` / `increment_failed_attempts()`).
  - Constant‑time password checks (argon2 verify + `hmac.compare_digest` on dummy values for non‑existent users).
- **MFA (TOTP)**
  - TOTP secrets generated via `pyotp.random_base32()`.
  - QR code provisioning with `otpauth://` URLs.
  - Backup codes stored as JSON, consumed on use.
  - TOTP verification with ±1 time step tolerance to handle clock skew.
- **Password reset**
  - One‑time, time-limited (1 hour) secure tokens via `secrets.token_urlsafe(32)`.
  - Tokens tracked in DB with `used` flag and expiry; invalidated on use.
  - Reset events logged to blockchain.

#### 4.2 Messaging

- **Confidentiality**
  - ECDH over P‑256 (SECP256R1) to derive a shared secret per message (ephemeral keys).
  - HKDF-SHA256 from shared secret to 256‑bit AES key.
  - AES‑256‑GCM encryption with random 96‑bit nonces.
- **Integrity & authenticity**
  - Ciphertext is signed using ECDSA with SHA‑256 (`Prehashed`).
  - Receiver verifies signature before decryption; failure aborts with error.
- **Perfect forward secrecy**
  - Ephemeral keys per message + optional symmetric ratchet (`init_ratchet`, `ratchet_encrypt`, `ratchet_decrypt`) for evolving keys.
- **Group messaging**
  - Random 256‑bit group key shared out‑of‑band.
  - AES‑GCM with distinct nonces per message.

#### 4.3 File Encryption

- **Key derivation**
  - PBKDF2-HMAC-SHA256 with ≥100,000 iterations and fresh 32‑byte salt per encryption.
  - Master key kept in memory only.
- **File key and encryption**
  - Random 256‑bit FEK for each file.
  - FEK encrypted using AES‑GCM under the master key; nonce stored in metadata.
  - File content encrypted in streaming mode with FEK and incrementing nonce per chunk.
- **Integrity and authenticity**
  - SHA‑256 hash of original plaintext file stored in metadata.
  - HMAC‑SHA256 computed over the encrypted file hash with the master key (returned to caller, and can be extended to be stored/verified for stronger authenticity).
  - On decryption, hash of decrypted file must match the original; otherwise the decrypted file is deleted.

#### 4.4 Blockchain Audit Ledger

- **Immutability**
  - Each block references previous block hash.
  - Transactions are summarized via Merkle root; any change invalidates root.
- **Proof of Work**
  - Hash must be below a difficulty target based on leading hex zeros.
  - Slows down arbitrary recomputation and tampering of the chain.
- **Verification**
  - `verify_block` checks previous hash, Merkle root, PoW, and recomputed hash.
  - `verify_chain` iterates over entire chain for integrity checks.
- **Event coverage**
  - Logs registration, login success/failures, TOTP issues, password reset requests/completions, file encrypt/decrypt operations, and message send/receive events.

### 5. Known Limitations

- **No hardware security module (HSM)**
  - Keys and secrets are kept in application memory and on disk (for some data) rather than in hardware.
  - For production deployments, an HSM or key management service would be recommended.

- **Single-node blockchain**
  - The blockchain is local and not distributed; consensus is “local PoW only”.
  - It protects against accidental modification and provides tamper‑evident logging, but not against a fully compromised server rewriting history.

- **Transport security assumed**
  - The code assumes deployment behind HTTPS.
  - If run over plain HTTP, an active MITM attacker could capture credentials and tokens.

- **Local session storage**
  - Session tokens are random secrets stored in the database and browser cookies (via Flask session).
  - Additional session hardening (same‑site cookies, secure flags, CSRF protection) should be configured at deployment time.

- **In‑memory rate limiting**
  - Rate limiting is implemented with an in‑memory dictionary; restarting the app clears it.
  - For production, a centralized store (e.g., Redis) should be used to enforce limits across processes/instances.

- **Client‑side key management**
  - Messaging keys are typically generated/downloaded via the web UI and stored client‑side (e.g., copy/paste).
  - Protecting these keys on the client machine is outside the scope of the server application.

### 6. Recommendations for Deployment

- Always deploy behind **TLS (HTTPS)**.
- Lock down environment variables and database file permissions.
- Use strong, unique admin and user passwords; encourage TOTP for all accounts.
- Regularly back up:
  - `cryptovault.db`
  - Encrypted files
  - Blockchain data (blocks + metadata)
- Periodically run `/api/verify_chain` and review `/audit` for anomalies.


