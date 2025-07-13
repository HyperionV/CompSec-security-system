# User Management & Authentication

This document details the user management and authentication features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. User Registration Flow

**Components Involved:**
- `gui/login_screen.py` (`LoginScreen` class)
- `gui/auth/registration_dialog.py` (`RegistrationDialog` class)
- `modules/auth.py` (`AuthManager` class, `GlobalUserSession` class)
- `modules/database.py` (`DatabaseManager` class)
- `modules/logger.py` (`SecurityLogger` class)
- `modules/key_manager.py` (`KeyManager` class)

**Sequence of Operations:**
1. **User Initiates Registration:** From `LoginScreen`, the user navigates to the "Register" tab or clicks a registration button that triggers `RegistrationDialog`.
2. **`RegistrationDialog` Input:**
   - User enters `username`, `email`, `passphrase`, and `confirm_passphrase`.
   - Real-time validation for email format and passphrase strength (`validate_email`, `validate_passphrase`, `calculate_password_strength`, `validate_passphrase_match` in `RegistrationDialog`).
   - Username availability is checked (`check_username_availability` in `RegistrationDialog` calls `auth_controller.check_username_availability`).
3. **`handle_registration` in `LoginScreen` (or `RegistrationDialog` if standalone):**
   - Collects user input.
   - Performs client-side validation (e.g., passphrase match).
   - Calls `auth_manager.register_user` from `AuthManager`.
4. **`AuthManager.register_user` (`modules/auth.py`):**
   - **Input Validation:** Re-validates `email` (`validate_email`) and `password` strength (`validate_password_strength`).
   - **Salt Generation:** Calls `generate_salt` to create a unique salt.
   - **Passphrase Hashing:** Calls `hash_password` to hash the user's passphrase with the generated salt.
   - **Recovery Code Generation & Hashing:** Calls `generate_recovery_code` and `hash_recovery_code`.
   - **Database Insertion:** Inserts user data (email, name, hashed password, salt, hashed recovery code) into the `users` table via `self.db.execute_query` (`DatabaseManager`).
   - **Key Generation (Optional):** If `generate_keys` is `True`, it calls `key_manager.create_user_keys` (`KeyManager`) to generate RSA keys for the new user. If key generation fails, it rolls back user creation.
   - **Logging:** Logs registration success or failure via `self.logger.log_activity` (`SecurityLogger`).
   - **Returns:** Success status and a message (including the recovery code if successful).
5. **`LoginScreen` (or `RegistrationDialog`) Response Handling:**
   - Displays success message and recovery code (via `RegistrationSuccessDialog`).
   - Clears registration form and switches to the login tab.

### 1.2. User Login Flow

**Components Involved:**
- `gui/login_screen.py` (`LoginScreen` class)
- `modules/auth.py` (`AuthManager` class, `GlobalUserSession` class)
- `modules/database.py` (`DatabaseManager` class)
- `modules/logger.py` (`SecurityLogger` class)
- `modules/mfa.py` (for MFA integration)

**Sequence of Operations:**
1. **User Initiates Login:** User enters `email` and `password` in the `LoginScreen` and clicks "Login" or presses Enter.
2. **`handle_login` in `LoginScreen`:**
   - Collects `email` and `password`.
   - Performs basic client-side validation.
   - Calls `auth_manager.initiate_login_flow` from `AuthManager`.
3. **`AuthManager.initiate_login_flow` (`modules/auth.py`):**
   - **Account Lockout Check:** Calls `check_account_lockout` to determine if the account is temporarily locked due to excessive failed attempts.
   - **Credential Verification:** Calls `verify_login_credentials` to retrieve user's salt and hashed password from the database (`DatabaseManager`) and then hashes the provided password with the stored salt to compare against the stored hash.
   - **Failed Attempt Management:** Updates `failed_attempts` and `locked_until` in the database (`DatabaseManager`) via `update_failed_attempts`.
   - **Progressive Delay:** Applies a progressive delay after multiple failed attempts (`apply_progressive_delay`).
   - **MFA Check:** If MFA is enabled for the user, triggers the MFA flow.
   - **Logging:** Logs login attempts (success/failure) via `self.logger.log_activity` (`SecurityLogger`).
   - **Returns:** Success status, a message, and `user_info` if successful.
4. **`LoginScreen` Response Handling:**
   - If login is successful, emits `login_successful` signal with `user_info`.
   - If login fails, displays an error message.

### 1.3. Account Recovery Flow

**Components Involved:**
- `gui/login_screen.py` (`LoginScreen` class)
- `modules/auth.py` (`AuthManager` class)
- `modules/database.py` (`DatabaseManager` class)
- `modules/logger.py` (`SecurityLogger` class)
- `modules/key_manager.py` (`KeyManager` class)

**Sequence of Operations:**
1. **User Initiates Recovery:** User navigates to the "Account Recovery" tab in `LoginScreen`.
2. **`LoginScreen` Input:** User enters `email`, `recovery_code`, `new_password`, and `confirm_password`.
3. **`handle_recovery` in `LoginScreen`:**
   - Collects input.
   - Performs basic client-side validation (e.g., password match, recovery code length).
   - Prompts for `old_password` to preserve keys (optional).
   - Calls `auth_manager.recover_account_with_code` from `AuthManager`.
4. **`AuthManager.recover_account_with_code` (`modules/auth.py`):**
   - **Recovery Code Verification:** Retrieves the hashed recovery code from the database and compares it with the hashed provided recovery code.
   - **Passphrase Update:** If the recovery code is valid, generates a new salt, hashes the `new_password`, and updates the user's `password_hash` and `salt` in the database.
   - **Key Preservation/Expiration:** If `old_password` is provided and valid, decrypts the existing private key with the old password and re-encrypts it with the `new_password` (`key_manager.update_private_key_passphrase`). If not provided or invalid, marks existing keys as expired and informs the user to generate new ones.
   - **Logging:** Logs account recovery attempts (success/failure) via `self.logger.log_activity` (`SecurityLogger`).
   - **Returns:** Success status and a message.
5. **`LoginScreen` Response Handling:**
   - Displays success or error messages.
   - Guides the user on next steps (e.g., login with new passphrase, generate new keys).

## 2. How to Use the Feature

### 2.1. User Registration
1. Launch the application (`main.py`).
2. In the `LoginScreen`, navigate to the "Register" tab.
3. Fill in the required fields:
   - **Email Address:** A unique, valid email address.
   - **Full Name:** Your desired display name.
   - **Passphrase:** A strong passphrase (minimum 8 characters, including uppercase, lowercase, numbers, and special characters).
   - **Confirm Passphrase:** Re-enter your passphrase.
4. Optionally, fill in Phone, Address, and Birth Date.
5. Click the "Register Account" button.
6. Upon successful registration, a dialog will appear displaying your **unique recovery code**. Copy this code and store it securely. This code is crucial for account recovery if you forget your passphrase.
7. You will be automatically redirected to the "Login" tab.

### 2.2. User Login
1. Launch the application (`main.py`).
2. In the `LoginScreen`, ensure you are on the "Login" tab.
3. Enter your registered **Email Address** and **Passphrase**.
4. Click the "Login" button.
5. If MFA is enabled, you will be prompted to enter a One-Time Passcode.
6. Upon successful login, you will be redirected to the main application interface.

### 2.3. Account Recovery
1. Launch the application (`main.py`).
2. In the `LoginScreen`, navigate to the "Account Recovery" tab.
3. Fill in the fields:
   - **Email Address:** Your registered email.
   - **Recovery Code:** The 16-character recovery code received during registration.
   - **New Passphrase:** Your desired new strong passphrase.
   - **Confirm New Passphrase:** Re-enter your new passphrase.
4. Optionally, you will be prompted to enter your **Old Passphrase** if you wish to preserve your existing RSA keys. If you don't provide it, your old keys will be invalidated, and you'll need to generate new ones after recovery.
5. Click the "Recover Account" button.
6. Upon successful recovery, you will receive a confirmation message and instructions on how to proceed (e.g., login with new passphrase, generate new keys).

## 3. Technical Knowledge about Security

### 3.1. Passphrase Hashing and Salting
- **Mechanism:** The application uses SHA-256 for passphrase hashing. Each user's passphrase is first concatenated with a **unique, cryptographically secure salt** (`secrets.token_hex(32)`) before hashing. The salt and the resulting hash are stored in the database, **never the plain passphrase**.
- **Purpose:**
  - **Salting:** Prevents pre-computation attacks like rainbow tables. Even if two users choose the same passphrase, their stored hashes will be different due to unique salts.
  - **Hashing:** Transforms the passphrase into a fixed-size string, making it irreversible. If the database is compromised, attackers only get hashes, not actual passphrases.
- **Relevance to Best Practices:** Adheres to industry best practices for secure password storage by using unique salts and strong, one-way hashing algorithms.

### 3.2. Passphrase Strength Enforcement
- **Mechanism:** Passphrases are validated against a regular expression (`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$`) that enforces a minimum length of 8 characters and requires a mix of lowercase letters, uppercase letters, numbers, and special characters.
- **Purpose:** Prevents weak passphrases that are susceptible to brute-force attacks or dictionary attacks.
- **Relevance to Best Practices:** Encourages users to create strong, hard-to-guess passphrases, significantly increasing the security of user accounts.

### 3.3. Account Lockout Mechanism
- **Mechanism:** After 5 consecutive failed login attempts for a specific email address, the account is temporarily locked for 5 minutes (`apply_progressive_delay`). The `failed_attempts` count and `locked_until` timestamp are stored and managed in the database.
- **Purpose:** Mitigates brute-force attacks and credential stuffing attempts by imposing a delay or lockout, making it computationally expensive for attackers to guess passphrases.
- **Relevance to Best Practices:** Implements a crucial defense mechanism against automated login attacks, protecting user accounts from unauthorized access.

### 3.4. Recovery Code Security
- **Mechanism:** A 16-character, URL-safe recovery code is generated for each user during registration (`secrets.token_urlsafe(12)[:16].upper()`). This code is displayed to the user *only once* and its **hash** is stored in the database. The plain recovery code is never stored.
- **Purpose:** Provides a secure out-of-band mechanism for users to regain access to their account if they forget their passphrase. By storing only the hash, the recovery code itself is not compromised if the database is breached.
- **Relevance to Best Practices:** Offers a robust account recovery method while minimizing the risk associated with storing sensitive recovery information.

### 3.5. Private Key Re-encryption on Passphrase Change
- **Mechanism:** When a user changes their passphrase, the existing private RSA key (which is encrypted with the old passphrase) is securely re-encrypted with the new passphrase. This involves decrypting the private key with the old passphrase and then encrypting it again with a key derived from the new passphrase (`key_manager.update_private_key_passphrase`). If the old password is not provided during account recovery, the existing keys are effectively invalidated, and the user is prompted to generate new ones.
- **Purpose:** Ensures that the user's private key remains secured under their current passphrase, maintaining the integrity and confidentiality of their cryptographic assets. Prevents a scenario where an attacker could gain access to the private key by knowing an old passphrase if only the account login password was updated.
- **Relevance to Best Practices:** A critical security measure that links the private key's encryption directly to the user's current passphrase, preventing unauthorized access to cryptographic functions even if an old passphrase is leaked. 