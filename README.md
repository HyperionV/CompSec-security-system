# SecurityApp

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/HyperionV/CompSec-security-system.git
    cd SecurityApp
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

## How to Run

1.  **Launch the Application:**
    Once the admin user is created, you can start the main application:

    ```bash
    python main.py
    ```

    Log in using the credentials of the admin user you just created. You will also be guided through a one-time setup for Multi-Factor Authentication (MFA).

2.  **Create Admin User:**
    To create admin accounts, run the following command and follow the on-screen prompts:

    ```bash
    python create_admin.py
    ```

    You will be prompted to enter a name, email, and password for the admin account.

    **NOTE**: To run this script, you need to first launch the application for the databases to be created, then you can run this script.

## Features

The application provides a tab-based interface for various security operations.

### 1. Key Management

- **Generate RSA Keys:** Create new RSA public/private key pairs.
- **View Keys:** View your existing keys, their status (active, expired), and validity periods.
- **Lifecycle Management:** Keys automatically expire after a predefined duration.

### 2. File Encryption & Decryption

- **Encrypt Files:** Select a file and a recipient (another user) to encrypt it using their public key.
- **Decrypt Files:** Decrypt files that were encrypted for you using your private key.

### 3. Digital Signatures

- **Sign Files:** Create a digital signature for a file using your private key.
- **Verify Signatures:** Verify the authenticity and integrity of a file by checking its digital signature against the sender's public key.

### 4. Public Keys

- **View Public Keys:** Browse and view the public keys of all registered users in the system.

### 5. QR Code Operations

- **Generate QR Codes:** Create QR codes from text or file content.
- **Read QR Codes:** Scan and decode QR codes from image files.

### 6. Account Management

- **Update Profile:** Change your personal information.
- **Change Password:** Update your login password.

### 7. Admin Panel (Admin Role Only)

- **User Management:** View all users, and enable/disable their accounts.
- **Security Audit Logs:** Review a detailed log of all critical activities performed within the application for security auditing.
