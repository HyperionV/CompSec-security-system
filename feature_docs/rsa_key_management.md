# RSA Key Management

This document details the RSA Key Management features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. Key Generation Flow

**Components Involved:**
- `gui/tabs/key_management_tab.py` (`KeyManagementTab` class)
- `modules/key_manager.py` (`KeyManager` class)
- `modules/auth.py` (`GlobalUserSession` class, `AuthManager` class for passphrase validation)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)

**Sequence of Operations:**
1. **User Initiates Key Generation:** From `KeyManagementTab`, the user clicks the "Generate New Keys" button.
2. **`KeyManagementTab.generate_keys`:**
   - Prompts the user for their passphrase via a `PasswordDialog` for encryption.
   - Calls `key_manager.create_user_keys` (from `KeyManager`) with the current user's ID and the provided passphrase.
   - Displays progress using `show_progress`.
3. **`KeyManager.create_user_keys` (`modules/key_manager.py`):**
   - **User Email Retrieval:** Fetches user email for logging purposes.
   - **RSA Keypair Generation:** Calls `generate_rsa_keypair`.
     - Uses `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key` to create a 2048-bit RSA private and public key pair.
     - Serializes the public key to PEM format.
     - Logs generation success/failure.
   - **Private Key Encryption:** Calls `encrypt_private_key`.
     - Generates a random `salt` and `nonce`.
     - Derives an AES key from the user's passphrase using `PBKDF2HMAC` (SHA256, 200,000 iterations).
     - Encrypts the private key (DER format) using `AESGCM` with the derived key and nonce.
     - Encodes `salt`, `nonce`, and `ciphertext` to base64 and stores encryption parameters.
     - Logs encryption success/failure.
   - **Expiration Calculation:** Calculates `expires_at` (90 days from `created_at`).
   - **Database Storage:** Calls `store_keys_in_database` to save the public key PEM and encrypted private key data (JSON string) in the `keys` table via `db.execute_query`.
   - **Logging:** Logs key creation status.
   - **Returns:** Success status and a message.
4. **`KeyManagementTab.generate_keys` Response Handling:**
   - Displays success or error messages (using `show_info`, `show_error`).
   - Updates the key status display (`update_key_status`).

### 1.2. Key Status and Lifecycle Flow

**Components Involved:**
- `gui/tabs/key_management_tab.py` (`KeyManagementTab` class)
- `modules/key_lifecycle.py` (`KeyLifecycleService` class)
- `modules/key_manager.py` (`KeyManager` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)

**Sequence of Operations:**
1. **Periodic Status Update (GUI):** A `QTimer` in `KeyManagementTab` triggers `update_key_status` every 30 seconds.
2. **`KeyManagementTab.update_key_status`:**
   - Retrieves the user's latest key from the database (`db.get_user_keys_by_id`).
   - Calculates `days_until_expiry` based on `expires_at`.
   - Determines the key status (`Valid`, `Near expiration`, `Expired`) and updates `status_label` and `key_metadata` accordingly.
   - Displays public key in `public_key_text`.
   - Manages button enable/disable states.
3. **Daily System Check (Backend):** `KeyLifecycleService.run_daily_lifecycle_check` is intended to be run periodically (e.g., daily) as a background task (likely initiated from `main.py`).
4. **`KeyLifecycleService.run_daily_lifecycle_check` (`modules/key_lifecycle.py`):**
   - Calls `update_all_expired_keys` which uses `db.update_expired_keys` to change status of expired keys to 'expired'.
   - Calls `update_all_expiring_keys` which uses `db.update_expiring_keys` to change status of keys within `warning_days` (7 days) to 'expiring'.
   - Calls `get_lifecycle_summary` for overall key health statistics.
   - Logs overall lifecycle check status.

### 1.3. Key Renewal Flow

**Components Involved:**
- `gui/tabs/key_management_tab.py` (`KeyManagementTab` class)
- `modules/key_manager.py` (`KeyManager` class)
- `modules/auth.py` (`GlobalUserSession` class)
- `modules/database.py` (`DatabaseManager` class)
- `modules/logger.py` (`SecurityLogger` class)

**Sequence of Operations:**
1. **User Initiates Key Renewal:** From `KeyManagementTab`, the user clicks the "Renew Existing Keys" button.
2. **`KeyManagementTab.renew_keys`:**
   - Prompts the user for their passphrase via a `PasswordDialog` (required to decrypt the old key for renewal).
   - Calls `key_manager.renew_user_keys` (from `KeyManager`) with the current user's ID and the provided passphrase.
   - Displays progress using `show_progress`.
3. **`KeyManager.renew_user_keys` (`modules/key_manager.py`):**
   - **Retrieve Old Key:** Fetches the existing encrypted private key and public key from the database.
   - **Decrypt Old Private Key:** Calls `decrypt_private_key` using the provided passphrase.
   - **Generate New Keypair:** Calls `generate_rsa_keypair` to create a new key pair.
   - **Encrypt New Private Key:** Calls `encrypt_private_key` to encrypt the newly generated private key with the user's passphrase.
   - **Update Database:** Updates the user's `public_key` and `encrypted_private_key` in the `keys` table, and sets new `created_at` and `expires_at` dates (new 90-day validity).
   - **Logging:** Logs key renewal status.
   - **Returns:** Success status and a message.
4. **`KeyManagementTab.renew_keys` Response Handling:**
   - Displays success or error messages.
   - Updates the key status display (`update_key_status`).

### 1.4. Key Export/Import (Implicit/Assumed from GUI)

While direct import/export functions are not explicitly detailed in `key_manager.py` as separate methods, the `KeyManagementTab` GUI provides buttons like "Save Public Key as .pem" and "Save Private Key as .pem". This implies a direct serialization of the currently displayed keys to a file.

**Flow for Saving Public Key:**
1. User clicks "Save Public Key as .pem".
2. `KeyManagementTab.save_public_key_pem`:
   - Opens a `QFileDialog` for file path selection.
   - Retrieves the public key PEM string from `self.public_key_text`.
   - Writes the PEM string to the selected file.

**Flow for Saving Private Key:**
1. User clicks "Save Private Key as .pem".
2. `KeyManagementTab.save_private_key_pem`:
   - Requires user to view the private key first (`view_private_key`) which decrypts it.
   - Prompts for passphrase to ensure authorized export of the sensitive private key.
   - Opens a `QFileDialog` for file path selection.
   - Retrieves the decrypted private key PEM (if successfully viewed).
   - Writes the PEM string to the selected file.

## 2. How to Use the Feature

### 2.1. Generating New Keys
1. Navigate to the "Key Management" tab in the main application.
2. Click the "Generate New Keys" button.
3. A dialog will appear asking for your **Passphrase**. Enter the passphrase you used during registration or your current login passphrase. This passphrase will be used to encrypt your private key.
4. Click "OK". The application will generate a new RSA 2048-bit key pair, encrypt your private key, and store both keys securely in the database.
5. You will see a success message, and the "Current Key Status" section will update to show your new key's details and validity.

### 2.2. Viewing Public and Private Keys
1. In the "Key Management" tab, the "Public Key" tab will automatically display your current public key in PEM format.
2. To view your **Private Key**, navigate to the "Private Key" tab and click the "View Private Key" button.
3. You will be prompted to enter your **Passphrase**. This is required to decrypt your private key for temporary display.
4. Upon successful decryption, your private key (in PEM format) will be displayed in the text area. It is highly recommended not to copy or share your private key unless absolutely necessary and securely handled.

### 2.3. Saving Keys to Files
- **Saving Public Key:**
  1. In the "Public Key" tab, click "Save Public Key as .pem".
  2. Choose a location and filename to save your public key. Public keys can be shared freely.
- **Saving Private Key:**
  1. First, view your private key as described in section 2.2.
  2. Once displayed, click "Save Private Key as .pem".
  3. Choose a secure location and filename. Exercise extreme caution when saving or sharing your private key.

### 2.4. Renewing Existing Keys
1. If your keys are nearing expiration (yellow status) or have expired (red status), click the "Renew Existing Keys" button.
2. You will be prompted for your **Passphrase**. Enter your current login passphrase. This is used to decrypt your old private key (if it's still valid) and encrypt your new one.
3. The application will generate a new key pair and replace your old keys in the database. The new keys will have a fresh 90-day validity period.

## 3. Technical Knowledge about Security

### 3.1. RSA Key Pair Generation
- **Mechanism:** The application generates 2048-bit RSA key pairs using `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`. This ensures a strong level of cryptographic security, as 2048-bit RSA keys are currently considered secure for general use.
- **Purpose:** RSA is an asymmetric cryptographic algorithm used for both encryption/decryption and digital signatures. The key pair consists of a public key (shareable) and a private key (kept secret).
- **Relevance to Best Practices:** Adhering to a sufficiently large key size (like 2048-bit or higher) is crucial for preventing brute-force attacks against the RSA algorithm.

### 3.2. Private Key Encryption (AES-256-GCM with PBKDF2)
- **Mechanism:** The private key is never stored in plain text. It is encrypted using **AES-256 in GCM (Galois/Counter Mode)**. The encryption key for AES is derived from the user's passphrase using **PBKDF2 (Password-Based Key Derivation Function 2)** with SHA256 as the hash algorithm and **200,000 iterations**. A unique, cryptographically secure `salt` and `nonce` are generated for each encryption operation and stored alongside the ciphertext.
- **Purpose:**
  - **AES-256-GCM:** Provides strong confidentiality and authenticated encryption (ensures both privacy and integrity of the encrypted private key).
  - **PBKDF2:** Deliberately slows down the process of deriving an encryption key from a passphrase, making brute-force and dictionary attacks against the passphrase computationally infeasible. The high iteration count (200,000) significantly increases the cost for attackers.
  - **Unique Salt & Nonce:** Prevents pre-computation attacks and ensures that even if two users have the same passphrase, their encrypted private keys will be different.
- **Relevance to Best Practices:** This is a robust and highly recommended method for protecting sensitive keys with a user-provided passphrase, aligning with modern cryptographic best practices.

### 3.3. Key Expiration and Lifecycle Management
- **Mechanism:** Each generated RSA key pair has a default validity period of **90 days**. The application actively tracks the `created_at` and `expires_at` timestamps for each key. It provides visual warnings (`expiring soon` status when less than 7 days remaining) and marks keys as `expired` automatically.
- **Purpose:** Enforces regular key rotation, which is a critical security practice. By limiting the lifespan of keys, the impact of a compromised key is reduced, and security posture is continuously improved. Expired keys cannot be used for cryptographic operations.
- **Relevance to Best Practices:** Key rotation minimizes the window of opportunity for an attacker to exploit a compromised key, even if the compromise is undetected for a period. This principle is fundamental to maintaining long-term cryptographic security.

### 3.4. Key Renewal Process
- **Mechanism:** The renewal process involves generating a **completely new RSA key pair** and replacing the old one in the database. The user's passphrase is used to decrypt the old private key (if it was still valid) to confirm authorization, but the new private key is independently generated and encrypted with the same (or new) passphrase.
- **Purpose:** Ensures that the key rotation truly replaces the underlying cryptographic material, rather than simply extending the validity period of a potentially compromised key. This maintains forward secrecy (compromise of one key doesn't compromise past communications) and strong security.
- **Relevance to Best Practices:** A robust key renewal mechanism is crucial for the overall security of the system, preventing the prolonged use of vulnerable or potentially compromised cryptographic keys. 