# File Encryption/Decryption

This document details the File Encryption and Decryption features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. File Encryption Flow

**Components Involved:**
- `gui/tabs/file_operations_tab.py` (`FileOperationsTab` class, `FileOperationWorker` class)
- `modules/file_crypto.py` (`FileCrypto` class)
- `modules/public_key_manager.py` (implicitly through `db.search_public_key_by_email`)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `cryptography` library (AESGCM, RSA padding)

**Sequence of Operations:**
1. **User Initiates Encryption:** From `FileOperationsTab`, the user selects an input file, chooses a recipient, selects an output format, and clicks "Encrypt File".
2. **`FileOperationsTab.encrypt_file`:**
   - Prompts for input file, recipient, and output location.
   - Validates user selections.
   - Initiates a `FileOperationWorker` thread to perform the encryption in the background.
   - Calls `file_crypto.encrypt_file` (from `FileCrypto`).
   - Displays progress using `show_progress`.
3. **`FileCrypto.encrypt_file` (`modules/file_crypto.py`):**
   - **Input Validation:** Checks if the input file exists and is not empty.
   - **Recipient Public Key Retrieval:** Calls `db.search_public_key_by_email` to fetch the recipient's public key from the database.
   - **Sender Info Retrieval:** Gets sender's email from the database.
   - **Session Key Generation:** Calls `generate_session_key` to create a random AES session key (`secrets.token_bytes(32)`).
   - **Large File Detection:** Calls `is_large_file` to check if the file size exceeds `large_file_threshold` (5MB).
   - **File Data Encryption:**
     - If `is_large_file` is `True`, it calls `encrypt_file_blocks`:
       - Reads the file in `self.block_size` (1MB) chunks.
       - For each block, generates a unique `nonce` (`generate_nonce`).
       - Encrypts the block using `AESGCM(session_key).encrypt(nonce, block_data, None)`.
       - Stores block metadata (block number, nonce, ciphertext length, ciphertext) in a header.
     - If `is_large_file` is `False`, it reads the entire file, generates a `nonce`, and encrypts the content using `AESGCM`.
   - **Session Key Encryption (RSA-OAEP):** Encrypts the `session_key` using the **recipient's RSA public key** with `padding.OAEP` and `hashes.SHA256`.
   - **Metadata Generation:** Creates JSON metadata including sender/recipient emails, original filename, file size, timestamp, algorithm, and `is_large_file` flag.
   - **Output File Handling:**
     - If `output_format` is `combined`:
       - Combines `encrypted_session_key` length, `encrypted_session_key`, `metadata` length, `metadata`, and `ciphertext` (or block header/data for large files) into a single `.enc` file.
     - If `output_format` is `separate`:
       - Saves `encrypted_session_key` and `metadata` into a `.key` file.
       - Saves `ciphertext` (or block header/data) into a `.enc` file.
   - **Logging:** Logs various stages of encryption (large file detection, block encryption, overall success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status, message, and output file paths.
4. **`FileOperationWorker` and `FileOperationsTab` Response Handling:**
   - `operation_completed` signal is emitted, which `FileOperationsTab.encryption_completed` handles.
   - Displays success or error messages (using `show_info`, `show_error`).
   - Hides the progress bar.

### 1.2. File Decryption Flow

**Components Involved:**
- `gui/tabs/file_operations_tab.py` (`FileOperationsTab` class, `FileOperationWorker` class)
- `modules/file_crypto.py` (`FileCrypto` class)
- `modules/key_manager.py` (implicitly for private key decryption via `key_manager.get_private_key`)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `cryptography` library (AESGCM, RSA padding)

**Sequence of Operations:**
1. **User Initiates Decryption:** From `FileOperationsTab`, the user selects an encrypted file, optionally a separate `.key` file, and clicks "Decrypt File".
2. **`FileOperationsTab.decrypt_file`:**
   - Prompts for encrypted file and optionally a separate key file.
   - Prompts for user's passphrase via a `PasswordDialog` to decrypt their private key.
   - Initiates a `FileOperationWorker` thread to perform decryption.
   - Calls `file_crypto.decrypt_file` (from `FileCrypto`).
   - Displays progress using `show_progress`.
3. **`FileCrypto.decrypt_file` (`modules/file_crypto.py`):**
   - **Input Parsing:** Determines if the input is a combined `.enc` file or separate `.enc` and `.key` files.
     - Reads header information (encrypted session key, metadata) and ciphertext.
   - **Private Key Retrieval:** Calls `key_manager.get_private_key` (from `KeyManager`) to retrieve the user's private key, decrypting it using the provided passphrase.
   - **Session Key Decryption (RSA-OAEP):** Uses the user's decrypted RSA private key to decrypt the `encrypted_session_key` with `padding.OAEP` and `hashes.SHA256` to obtain the original AES `session_key`.
   - **File Data Decryption:**
     - If `is_large_file` is `True` (from metadata), it calls `decrypt_file_blocks`:
       - Iterates through encrypted blocks, decrypting each using `AESGCM(session_key).decrypt(nonce, ciphertext, None)`.
       - Validates block order and integrity.
       - Reconstructs the original plaintext.
     - If `is_large_file` is `False`, it decrypts the entire ciphertext using `AESGCM`.
   - **Output File Writing:** Writes the decrypted plaintext to a new file, typically removing the `.enc` extension.
   - **Logging:** Logs various stages of decryption (large file processing, block decryption, overall success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status, message, and output file path.
4. **`FileOperationWorker` and `FileOperationsTab` Response Handling:**
   - `operation_completed` signal is emitted, which `FileOperationsTab.decryption_completed` handles.
   - Displays success or error messages.
   - Hides the progress bar.

## 2. How to Use the Feature

### 2.1. Encrypting a File
1. Navigate to the "File Operations" tab in the main application.
2. In the "Encrypt File" section:
   - Click "Browse" next to "File:" to select the file you wish to encrypt.
   - Choose a "Recipient:" from the dropdown list. This list contains users whose public keys you have imported.
   - Select an "Output Format:" (Combined `*.enc` or Separate `*.enc + *.key`).
3. Click the "Encrypt File" button.
4. A "Save Encrypted File" dialog will appear. Choose a location and filename for the output encrypted file (e.g., `document.pdf.enc`).
5. Confirm the encryption in the prompt.
6. A progress bar will show the encryption status. Upon completion, a success message will be displayed.

### 2.2. Decrypting a File
1. Navigate to the "File Operations" tab in the main application.
2. In the "Decrypt File" section:
   - Click "Browse" next to "Encrypted File:" to select the `.enc` file you wish to decrypt.
   - If the encrypted file has a separate `.key` file, the system will automatically look for it in the same directory. (Future enhancement: allow explicit selection if needed).
3. Click the "Decrypt File" button.
4. A dialog will appear asking for your **Passphrase**. Enter your current login passphrase. This is required to decrypt your private key, which is then used to decrypt the file's session key.
5. Choose a location and filename for the decrypted output file (the original filename will be suggested).
6. Confirm the decryption in the prompt.
7. A progress bar will show the decryption status. Upon completion, a success message will be displayed, and the original file will be accessible.

## 3. Technical Knowledge about Security

### 3.1. Hybrid Encryption (AES-256-GCM + RSA-OAEP)
- **Mechanism:** The application employs a hybrid encryption scheme:
  - **AES-256-GCM:** A symmetric encryption algorithm used for encrypting the actual file data. It provides strong confidentiality and data authenticity (integrity and origin verification) through its Galois/Counter Mode.
  - **RSA-OAEP:** An asymmetric encryption algorithm used for encrypting the randomly generated AES session key. RSA with Optimal Asymmetric Encryption Padding (OAEP) ensures semantic security against chosen-plaintext attacks and provides randomness to the encryption process.
- **Purpose:** Combining symmetric and asymmetric cryptography leverages the strengths of both: AES is fast for large data encryption, while RSA provides secure key exchange without needing to share a symmetric key in advance.
- **Relevance to Best Practices:** This is a standard and highly recommended approach for secure data transmission and storage, ensuring both efficiency and strong cryptographic protection.

### 3.2. Large File Processing with Block Encryption
- **Mechanism:** For files larger than 5MB (`large_file_threshold`), the application encrypts data in 1MB blocks (`block_size`). Each block is encrypted with `AES-256-GCM` using a **unique, randomly generated nonce** for that specific block. A JSON header containing metadata and pointers to these encrypted blocks is prepended to the encrypted file.
- **Purpose:** Efficiently handles large files by processing them in manageable chunks, avoiding excessive memory consumption. Using unique nonces per block is critical to prevent nonce reuse attacks, which would severely compromise AES-GCM security.
- **Relevance to Best Practices:** Essential for practical file encryption, enabling the handling of large datasets securely without performance bottlenecks. Strict adherence to unique nonce usage for each AES-GCM encryption is a fundamental security requirement.

### 3.3. Output Formats (Combined vs. Separate)
- **Mechanism:** Users can choose to save the encrypted output as a single `.enc` file (containing encrypted session key, metadata, and ciphertext) or as two separate files (`.enc` for ciphertext, `.key` for encrypted session key and metadata).
- **Purpose:** Offers flexibility. The combined format is simpler for single-file distribution. The separate format allows for key management (e.g., distributing the `.key` file out-of-band) or for scenarios where the encrypted data might be stored separately from its key material.
- **Relevance to Best Practices:** While providing flexibility, the separate key file needs to be managed with equal, if not greater, care than the encrypted data itself, as its compromise directly leads to data decryption.

### 3.4. Secure Key Usage and Private Key Protection
- **Mechanism:** Decryption requires the user's private key. This private key is itself encrypted at rest using AES-256-GCM with a key derived from the user's passphrase via PBKDF2 (as detailed in RSA Key Management documentation). The application securely handles passphrase input (via `PasswordDialog`) and only decrypts the private key in memory for the duration of the decryption operation, never writing it to disk in plain text.
- **Purpose:** Ensures that even if an attacker gains access to the encrypted file and the database, they cannot decrypt the file without the user's passphrase, which unlocks the private key.
- **Relevance to Best Practices:** Strong protection of the private key is paramount. Encrypting the private key with a strong passphrase and limiting its plaintext presence in memory are vital security controls. 