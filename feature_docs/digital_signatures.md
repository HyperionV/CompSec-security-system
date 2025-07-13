# Digital Signatures

This document details the Digital Signature features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. File Signing Flow

**Components Involved:**
- `gui/tabs/signature_tab.py` (`SignatureTab` class)
- `modules/digital_signature.py` (`DigitalSignature` class)
- `modules/key_manager.py` (for private key decryption via `key_manager.get_private_key`)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `cryptography` library (RSA-PSS padding, SHA256 hashes)

**Sequence of Operations:**
1. **User Initiates Signing:** From `SignatureTab`, the user selects a file to sign and clicks "Create Digital Signature".
2. **`SignatureTab.sign_file`:**
   - Prompts for input file.
   - Prompts the user for their private key passphrase via a `QInputDialog`.
   - Calls `digital_signature.sign_file` (from `DigitalSignature`) with the input file path and passphrase.
   - Handles saving the generated `.sig` file.
3. **`DigitalSignature.sign_file` (`modules/digital_signature.py`):**
   - **File Existence Check:** Verifies if the `file_path` exists.
   - **Private Key Retrieval & Decryption:** Calls `key_manager.get_private_key` (from `KeyManager`) using the `user_email` and provided `passphrase` to get the signer's private key. If decryption fails, the process stops.
   - **File Data Reading:** Reads the entire `file_data` into memory.
   - **File Hash Calculation (for Metadata):** Calculates `SHA256` hash of the `file_data` (`hashlib.sha256`) for inclusion in the signature metadata.
   - **Digital Signing (RSA-PSS):** Uses the decrypted `private_key.sign` method.
     - The actual `file_data` (not just its hash) is passed for signing.
     - `padding.PSS` (Probabilistic Signature Scheme) with `MGF1(SHA256)` is used for padding, which adds randomness to the signature generation, preventing certain attacks.
     - `hashes.SHA256()` specifies the hashing algorithm used internally by PSS.
   - **Metadata Creation:** Calls `_create_signature_metadata` to generate a JSON dictionary containing signer email, original filename, timestamp, file hash, and algorithm details.
   - **Signature File Saving:** Calls `_save_signature_file`.
     - Combines the JSON `metadata` and the raw `signature` bytes into a single `.sig` file, separated by a delimiter (`---SIGNATURE---`).
     - The file is saved in `data/signatures/` with a timestamped name (e.g., `filename_YYYYMMDD_HHMMSS.sig`).
   - **Logging:** Logs signature creation status (success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status and the path to the generated signature file.
4. **`SignatureTab.sign_file` Response Handling:**
   - Displays success or error messages (using `show_info`, `show_error`).
   - Clears the input field.

### 1.2. Signature Verification Flow

**Components Involved:**
- `gui/tabs/signature_tab.py` (`SignatureTab` class)
- `modules/signature_verification.py` (`SignatureVerification` class)
- `modules/database.py` (`DatabaseManager` class - for retrieving public keys, accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `cryptography` library (RSA-PSS padding, SHA256 hashes)

**Sequence of Operations:**
1. **User Initiates Verification:** From `SignatureTab`, the user selects the original file and its corresponding `.sig` signature file, then clicks "Verify Signature".
2. **`SignatureTab.verify_signature`:**
   - Prompts for `original_file` and `signature_file` paths.
   - Calls `signature_verification.verify_signature` (from `SignatureVerification`).
   - Displays verification results in `results_text`.
3. **`SignatureVerification.verify_signature` (`modules/signature_verification.py`):**
   - **File Existence Check:** Verifies if both `file_path` and `signature_path` exist.
   - **Signature File Parsing:** Calls `_parse_signature_file` to extract the JSON `metadata` and raw `signature_bytes` from the `.sig` file.
   - **Original File Data Reading:** Reads the entire `file_data` into memory.
   - **Hash Comparison:** Calculates `SHA256` hash of the `file_data` and compares it to the `file_hash` stored in the `metadata`. If they don't match, verification fails immediately (file integrity compromised).
   - **Public Key Retrieval & Verification:**
     - **Direct Verification (Optional):** If the `signer_email` in metadata matches the current logged-in user, it first tries `_try_direct_verification` using the user's own public key from the database (`db.get_user_public_key`).
     - **Iterative Verification:** If direct verification fails or is not applicable, it retrieves **all available public keys** from the database (`_get_all_public_keys`, which includes keys imported by the user). It then iterates through these public keys.
     - For each public key, it attempts `public_key.verify`:
       - Verifies the `signature_bytes` against the original `file_data`.
       - Uses `padding.PSS` with `MGF1(SHA256)` and `hashes.SHA256()` for the verification process, which must match the signing parameters.
   - **Logging:** Logs verification status (success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status and a detailed message.
4. **`SignatureTab.verify_signature` Response Handling:**
   - Updates `results_text` with a green success message or a red error message.
   - If successful, it attempts to parse and display additional metadata (signer, timestamp, original filename, hash) from the `.sig` file for user clarity.

## 2. How to Use the Feature

### 2.1. Creating a Digital Signature
1. Navigate to the "Signature" tab in the main application.
2. In the "Sign File" section:
   - Click "Browse" next to "File to Sign:" to select the document or file you want to digitally sign.
3. Click the "Create Digital Signature" button.
4. A dialog will appear asking for your **Private Key Passphrase**. Enter the passphrase you use to encrypt your private RSA key.
5. A "Save Signature File" dialog will appear. Choose a location and filename for the `.sig` file (e.g., `document.pdf.sig`). The system will suggest a default name based on the original file.
6. Upon successful signing, a confirmation message will be displayed, and the `.sig` file will be created.

### 2.2. Verifying a Digital Signature
1. Navigate to the "Signature" tab in the main application.
2. In the "Verify Signature" section:
   - Click "Browse" next to "Original File:" to select the original document or file that was signed.
   - Click "Browse" next to "Signature File (.sig):" to select the corresponding `.sig` file.
3. Click the "Verify Signature" button.
4. The "Verification Results" section will update:
   - If the signature is valid and the file has not been tampered with, a green "VERIFICATION SUCCESSFUL" message will appear, along with details like the signer's email, timestamp, and original file hash.
   - If the signature is invalid (e.g., file was modified, wrong key used, or signature is corrupted), a red "VERIFICATION ERROR" message will be displayed with details about the failure.

## 3. Technical Knowledge about Security

### 3.1. SHA-256 Hashing for Integrity
- **Mechanism:** Before signing, the entire content of the file is hashed using **SHA-256 (Secure Hash Algorithm 256)**. This produces a fixed-size, unique "fingerprint" of the file.
- **Purpose:** Hashing ensures **data integrity**. If even a single bit of the original file is changed after signing, its SHA-256 hash will be completely different, causing signature verification to fail. This immediately alerts the verifier to any tampering.
- **Relevance to Best Practices:** SHA-256 is a widely accepted, collision-resistant hash function, making it suitable for ensuring the integrity of signed data.

### 3.2. RSA-PSS for Digital Signatures
- **Mechanism:** The application uses **RSA with PSS (Probabilistic Signature Scheme) padding** for creating digital signatures. PSS adds a random component to the signature generation process, making each signature unique even for the same message and key. The private RSA key is used for signing, and the corresponding public RSA key is used for verification.
- **Purpose:**
  - **Authentication:** Proves that the signature was indeed created by the holder of the private key, thus authenticating the sender.
  - **Non-repudiation:** Prevents the signer from falsely denying that they signed a document.
  - **Probabilistic Security:** PSS is designed to be provably secure under certain cryptographic assumptions, enhancing the overall security of the signature scheme compared to older padding methods like PKCS#1 v1.5.
- **Relevance to Best Practices:** RSA-PSS is the recommended padding scheme for RSA signatures due to its enhanced security properties and provable security guarantees. Signing the *hash* of the data rather than the data itself is a standard practice for efficiency, but here the `file_data` is directly passed to `private_key.sign` which then hashes it internally as part of the PSS operation.

### 3.3. Private Key Protection for Signing
- **Mechanism:** To create a digital signature, the user's private RSA key is required. This private key is encrypted at rest (as detailed in the RSA Key Management documentation) and is only decrypted in memory after the user provides their correct passphrase. The application ensures that the private key is handled securely and is not exposed.
- **Purpose:** The security of digital signatures directly depends on the confidentiality of the private key. If an attacker gains access to the private key, they can forge signatures, impersonating the legitimate signer. Prompting for the passphrase ensures authorized use.
- **Relevance to Best Practices:** Protecting the private key through encryption and secure handling during signing operations is fundamental to the trustworthiness of digital signatures.

### 3.4. Verification with Public Keys
- **Mechanism:** Signature verification can be performed using any public key available to the system (either the current user's own public key or any public keys imported from others). The `SignatureVerification` module iterates through available public keys to find one that successfully verifies the signature against the original file's content.
- **Purpose:** Allows anyone with the signer's public key to verify the authenticity and integrity of a signed file, without needing access to the signer's private key or any secret information.
- **Relevance to Best Practices:** Public key cryptography enables trust in digital interactions by decoupling signing (private key) from verification (public key). Importing and managing public keys securely is important for reliable verification. 