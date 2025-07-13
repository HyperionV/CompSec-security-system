# Multi-Factor Authentication (MFA)

This document details the Multi-Factor Authentication (MFA) feature of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. Email OTP (One-Time Passcode) Flow

**Components Involved:**
- `gui/mfa_screen.py` (`MFAScreen` class)
- `modules/mfa.py` (`MFAManager` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias in `mfa.py`)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias in `mfa.py`)

**Sequence of Operations:**
1. **User Initiates OTP Request:** From `MFAScreen`, the user clicks the "Send OTP" button.
2. **`MFAScreen.send_otp`:**
   - Calls `mfa_manager.generate_otp` (from `MFAManager`) with the current user's ID.
   - Starts a countdown timer for OTP expiry.
3. **`MFAManager.generate_otp` (`modules/mfa.py`):**
   - **User Email Retrieval:** Fetches the user's email from the `users` table via `db.execute_query`.
   - **OTP Creation:** Calls `create_otp` to generate a 6-digit OTP code (`generate_otp_code`) and calculates its expiry time (5 minutes from generation).
   - **Database Storage:** Stores the OTP code, expiry time, and user ID in the `otp_codes` table via `db.execute_query`.
   - **OTP Email Sending:** Calls `send_otp_email`.
     - If SMTP is enabled and configured, it calls `_send_real_email` using `smtplib` to send an actual email.
     - Otherwise, it falls back to `_simulate_email`, which prints the OTP to the console for testing/development.
   - **Logging:** Logs OTP generation and sending status (success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status, a message, and OTP data (including the code for testing purposes).
4. **`MFAScreen.send_otp` Response Handling:**
   - Updates `otp_status_label` with success/failure message and countdown.
   - Enables the "Verify OTP" button.

5. **User Enters OTP:** User types the received OTP code into the `otp_input` field and clicks "Verify OTP" or presses Enter.
6. **`MFAScreen.verify_otp`:**
   - Retrieves the entered OTP code.
   - Calls `mfa_manager.verify_otp` (from `MFAManager`) with user ID and the entered OTP.
7. **`MFAManager.verify_otp` (`modules/mfa.py`):**
   - **OTP Retrieval & Validation:** Queries the `otp_codes` table for the provided OTP associated with the user and checks if it's expired or already used.
   - **Mark as Used:** If the OTP is valid and not expired/used, updates the `used` status to `1` in the database via `db.execute_query`.
   - **Logging:** Logs OTP verification status (success/failure) via `security_logger.log_activity`.
   - **Returns:** Success status and a message.
8. **`MFAScreen.verify_otp` Response Handling:**
   - If successful, emits `mfa_successful` signal.
   - If verification fails, displays an error message.

### 1.2. TOTP (Time-Based One-Time Passcode) Flow

**Components Involved:**
- `gui/mfa_screen.py` (`MFAScreen` class)
- `modules/mfa.py` (`MFAManager` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias in `mfa.py`)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias in `mfa.py`)
- `pyotp` library
- `qrcode` library

**Sequence of Operations:**
1. **`MFAScreen` Initialization (`initialize_mfa_options`):**
   - Checks if TOTP is already set up for the user by calling `mfa_manager.has_totp_setup`.
   - If `True`, calls `load_existing_totp`.
   - If `False`, displays a message prompting setup.
2. **`MFAScreen.load_existing_totp` (if TOTP exists):**
   - Calls `mfa_manager.get_user_totp_qr` to retrieve the TOTP secret and QR code (base64 encoded).
   - Calls `display_qr_code` to show the QR image and `manual_key_label.setText` to display the manual entry key.
3. **User Initiates TOTP Setup (if not set up):** User clicks the "Setup TOTP" button.
4. **`MFAScreen.setup_totp`:**
   - Calls `mfa_manager.setup_user_totp` with user ID and email.
5. **`MFAManager.setup_user_totp` (`modules/mfa.py`):**
   - **Secret Generation:** Calls `generate_totp_secret` to generate a new TOTP secret using `pyotp.random_base32()`.
   - **Database Storage:** Stores the TOTP secret for the user in the `users` table via `db.execute_query`.
   - **QR Code Generation:** Uses `pyotp.TOTP` to generate the OTP URI, then `qrcode.make` to create a QR code image. This image is then converted to base64 for display.
   - **Logging:** Logs TOTP setup status.
   - **Returns:** Success status and a dictionary containing the secret and base64 QR code.
6. **`MFAScreen.setup_totp` Response Handling:**
   - Calls `display_qr_code` to show the generated QR code.
   - Updates `manual_key_label` with the secret key.
   - Changes button text to "Show QR Code" and enables "Verify TOTP" button.

7. **User Enters TOTP:** User scans the QR code with an authenticator app (e.g., Google Authenticator) or manually enters the key, then types the 6-digit TOTP code into the `totp_input` field and clicks "Verify TOTP" or presses Enter.
8. **`MFAScreen.verify_totp`:**
   - Retrieves the entered TOTP code.
   - Calls `mfa_manager.verify_user_totp` with user ID and the entered token.
9. **`MFAManager.verify_user_totp` (`modules/mfa.py`):**
   - **Secret Retrieval:** Fetches the user's TOTP secret from the database.
   - **TOTP Verification:** Calls `verify_totp` (which uses `pyotp.TOTP(secret).verify(token)`) to check the validity of the entered token against the stored secret.
   - **Logging:** Logs TOTP verification status.
   - **Returns:** Success status and a message.
10. **`MFAScreen.verify_totp` Response Handling:**
    - If successful, emits `mfa_successful` signal.
    - If verification fails, displays an error message.

## 2. How to Use the Feature

### 2.1. Email OTP Verification
1. After a successful login attempt, if MFA is required, you will be directed to the `MFAScreen`.
2. Click the "Send OTP" button in the "Email OTP Verification" section.
3. Check your registered email address for a 6-digit OTP code (also visible in the console if SMTP is not configured).
4. Enter the received 6-digit code into the "OTP Code" field.
5. Click the "Verify OTP" button.
6. If the code is correct and not expired, you will gain access to the main application.

### 2.2. TOTP (Google Authenticator) Setup and Verification

**Setup:**
1. After logging in, if MFA is required and TOTP is not yet set up, you will see a "Setup TOTP" button in the "TOTP (Google Authenticator)" section.
2. Click "Setup TOTP". A QR code and a manual entry key will be displayed.
3. Open your Google Authenticator (or compatible) app on your mobile device.
4. Scan the displayed QR code with your authenticator app. Alternatively, manually enter the provided key into the app.
5. The authenticator app will now generate 6-digit codes that refresh periodically.

**Verification:**
1. After setting up TOTP, whenever MFA is required, enter the current 6-digit code displayed in your authenticator app into the "TOTP Code" field on the `MFAScreen`.
2. Click the "Verify TOTP" button.
3. If the code is correct, you will gain access to the main application.

## 3. Technical Knowledge about Security

### 3.1. One-Time Passcodes (OTP)
- **Mechanism:** The application generates 6-digit OTPs using `pyotp` (specifically, `pyotp.HOTP` based on a random seed, though for email OTP, it's typically just a randomly generated number stored with an expiry). These codes are stored in the database with a 5-minute expiry (`otp_expiry_minutes`). Each OTP can only be used once.
- **Purpose:** Adds an additional layer of security beyond just a passphrase. Even if an attacker compromises a user's passphrase, they cannot log in without access to the user's email to retrieve the OTP.
- **Relevance to Best Practices:** OTPs are a standard form of 2FA. The 5-minute expiry limits the time window for an attacker to use a leaked OTP.

### 3.2. Time-Based One-Time Passcodes (TOTP)
- **Mechanism:** TOTP uses a shared secret key (generated via `pyotp.random_base32()`) and the current time to generate a 6-digit code that changes every 30 seconds (default for TOTP). The secret is stored securely in the database (`users` table). `pyotp.TOTP(secret).verify(token)` is used for validation.
- **Purpose:** Provides a strong form of 2FA that doesn't rely on network communication (like email OTP). The codes are generated offline on the user's device, making it resistant to phishing and man-in-the-middle attacks that target SMS or email-based OTPs.
- **Relevance to Best Practices:** TOTP, as implemented via authenticator apps, is a highly recommended and widely adopted 2FA method due to its robustness against common attack vectors.

### 3.3. Account Lockout for Failed OTP Attempts
- **Mechanism:** While `modules/auth.py` handles general login lockout, the MFA process itself will typically have mechanisms to prevent brute-force attacks on OTP/TOTP inputs (e.g., rate limiting on the `verify_otp` or `verify_totp` calls, or temporary lockouts). Although not explicitly detailed in `mfa.py` for MFA-specific lockouts, it's a general security principle that should be applied.
- **Purpose:** Prevents attackers from guessing OTP/TOTP codes through repeated attempts.
- **Relevance to Best Practices:** Critical for preventing brute-force attacks on the second factor. Rate limiting and temporary lockouts are essential to protect against automated attacks.

### 3.4. Secure SMTP Configuration (Optional)
- **Mechanism:** The `MFAManager` allows for optional configuration of real SMTP settings (`configure_smtp`) using `smtplib` with TLS encryption and user authentication. If not configured, it simulates email sending by printing to the console.
- **Purpose:** For production environments, using a secure SMTP server ensures that OTP emails are sent reliably and securely over an encrypted channel, preventing eavesdropping on email content.
- **Relevance to Best Practices:** Secure email communication for sensitive data like OTPs is vital. Using TLS and proper authentication for SMTP connections is a standard security practice. 