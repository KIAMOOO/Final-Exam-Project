## CryptoVault User Guide

This guide shows how to use the CryptoVault web interface and Python API for authentication, secure messaging, file encryption, and audit viewing.

---

### 1. Getting Started

1. **Install dependencies**

```bash
pip install -r requirements.txt
```

2. **Configure environment (optional but recommended)**

- Create a `.env` file with values like:

```text
MAILJET_API_KEY=your_api_key
MAILJET_API_SECRET=your_secret
FROM_EMAIL=you@example.com
FROM_NAME=CryptoVault
```

3. **Run the web app**

```bash
python src/main.py
```

4. **Open the UI**

- Go to `http://localhost:5000` in your browser.

---

### 2. Using the Web Interface

#### 2.1 Registration and Login

1. **Register**
   - Click **Register** (or **Sign Up**) from the home page.
   - Enter:
     - **Username** – 3–20 characters, letters/digits/underscores only.
     - **Password** – at least 8 chars, must include uppercase, lowercase, digit, and special character.
     - **Email** – must be a valid email format and unique.
   - Submit. On success you’ll see a success message.

2. **Login**
   - Go to **Login**.
   - Enter your username and password.
   - If TOTP is **not** yet enabled, you’ll be logged in and redirected to the dashboard.
   - If TOTP **is** enabled, you must also enter a 6‑digit TOTP code from your authenticator app (or a backup code).

3. **Logout**
   - Click **Logout** in the navigation bar to end your session.

#### 2.2 Enabling TOTP (Two‑Factor Authentication)

1. Log in and go to the **Dashboard**.
2. Click the **TOTP / 2FA** setup option (if present) or follow the on‑screen instructions.
3. When you start setup:
   - A **QR code** is displayed for you to scan with Google Authenticator / Authy / similar.
   - A list of **backup codes** is shown. Save these in a safe place (each can be used once).
4. After scanning, enter the current 6‑digit code shown in your app to **confirm**.
5. If the code is valid, TOTP is enabled. From now on, login requires:
   - Username + password
   - TOTP code (or a backup code)

#### 2.3 Password Reset Flow

1. From the login page, click **Forgot password?**.
2. Enter your **username or email**.
3. If configured correctly and the user exists:
   - A one‑time reset link is emailed to the associated address.
4. Click the link in the email:
   - You’ll be taken to a **Reset Password** page.
   - Enter a new password that satisfies the strength rules and submit.
5. On success, your old sessions remain invalid, and you can log in with the new password.

---

### 3. Secure Messaging

#### 3.1 Generating Keys

1. Log in and go to the **Messaging** page.
2. Click **Generate Keypair**.
3. The page will display:
   - Your **private key** (PEM) – keep this secret.
   - Your **public key** (PEM) – share with others.
4. Save your keys securely (e.g., copy to a password manager or a secure local file).

#### 3.2 Sending a Secure Message

To send a message to another user:

1. Obtain the **recipient’s public key** (PEM).
2. On the Messaging page:
   - Paste the recipient’s public key into the **Recipient Public Key** field.
   - Paste your own **private key** into the **Sender Private Key** field.
   - Type your message into the message box.
3. Click **Encrypt / Send** (exact label may vary).
4. The app:
   - Performs ECDH to derive a shared secret.
   - Uses HKDF to derive an AES‑256‑GCM key.
   - Encrypts and signs the message.
5. You will see a JSON object representing the encrypted message (including nonce, ciphertext, auth tag, ephemeral key, and signature).
6. Send this encrypted JSON to the recipient via any channel (email, chat, etc.).

#### 3.3 Receiving and Decrypting a Message

1. On the Messaging page, paste:
   - The **encrypted message JSON** you received.
   - Your **private key** in the appropriate field.
   - The **sender’s public key** (PEM) into the sender key field.
2. Click **Decrypt**.
3. The app:
   - Verifies the ECDSA signature.
   - Derives the correct AES key and decrypts the ciphertext.
4. If everything matches, the original plaintext message is displayed.

---

### 4. File Encryption and Decryption

#### 4.1 Encrypting a File

1. Log in and go to the **Files** page.
2. Under **Encrypt File**:
   - Click **Choose File** and select the file to encrypt.
   - Enter an **encryption password** (this is separate from your login password; choose a strong one).
3. Submit the form.
4. The app:
   - Computes SHA‑256 of the original file.
   - Derives a master key from your password via PBKDF2.
   - Generates a random FEK and encrypts it with the master key.
   - Encrypts the file in chunks with AES‑256‑GCM.
5. On success, you receive:
   - Path/filename of the encrypted file (usually in `encrypted_files/`).
   - Metadata (hashes, salt, etc.) for debugging / audit.

#### 4.2 Decrypting a File

1. Still on the **Files** page, under **Decrypt File**:
   - Provide the path/name of the encrypted file (or use the UI control if present).
   - Enter the **same password** used during encryption.
2. Submit the request.
3. The app:
   - Reads the file’s metadata (salt, encrypted FEK, nonces, original hash).
   - Re‑derives the master key, decrypts the FEK, and then decrypts file chunks.
   - Verifies that the decrypted file hash matches the stored original hash.
4. On success, it returns:
   - A **download link** for the decrypted file (e.g., `decrypted_<original_name>`).
5. Click the download link to save the decrypted file locally.

> If the password is wrong or the file has been tampered with, decryption fails and you receive an error message instead of a file.

---

### 5. Audit Trail and Blockchain

#### 5.1 Viewing the Audit Trail

1. Log in and go to the **Audit** page.
2. The page shows:
   - A list of blocks in the blockchain.
   - For each block: index, timestamp, previous hash, Merkle root, and transactions.
3. Each **transaction** describes a security event, e.g.:
   - `AUTH_LOGIN` – login attempts (success or failure).
   - `FILE_ENCRYPT`, `FILE_DECRYPT` – file operations.
   - `MESSAGE_SEND`, `MESSAGE_RECEIVE` – messaging events.
   - `AUTH_PASSWORD_RESET_REQUEST`, `AUTH_PASSWORD_RESET` – password reset events.

#### 5.2 Verifying Chain Integrity

1. On the Audit page (or via API), click **Verify Chain**.
2. The server:
   - Iterates through all blocks.
   - Checks previous hash links, Merkle roots, PoW difficulty, and block hashes.
3. The result indicates whether the chain is valid or if tampering is detected.

---

### 6. Python API Usage (Short Examples)

You can also use CryptoVault programmatically:

```python
from src.cryptovault import CryptoVault

vault = CryptoVault()

# Register
success, error = vault.register("alice", "StrongPass123!", "alice@example.com")

# Login
success, error, token = vault.login("alice", "StrongPass123!", totp_code="123456")

# File encryption
ok, err, meta = vault.encrypt_file("document.pdf", "file_password", "alice")

# File decryption
ok, err = vault.decrypt_file(meta["encrypted_file"], "file_password", "alice")

# Access audit trail
chain = vault.get_audit_trail()
print("Blocks:", len(chain))
```

---

### 7. Best Practices for Users

- Use **unique, strong passwords** for login and for file encryption.
- **Enable TOTP** to protect against credential theft.
- Never share your **private keys** or backup codes.
- Back up:
  - Encrypted files,
  - Your messaging keys,
  - TOTP backup codes.
- Regularly review the **Audit** page for any unexpected activity.


