# Security Application

A comprehensive desktop security application implementing **17 core security functionalities** including user management, multi-factor authentication, RSA key management, file encryption/decryption, digital signatures, QR code operations, and role-based access control.

Built as a complete course project for Computer Security, this application demonstrates modern cryptographic practices and secure software development principles.

## 🔐 Features Overview

### Complete Security Suite (17 Functionalities)

| Feature                         | Description                                                 | Status         |
| ------------------------------- | ----------------------------------------------------------- | -------------- |
| **User Registration**           | Secure account creation with passphrase strength validation | ✅ Implemented |
| **Multi-Factor Authentication** | OTP/TOTP with Google Authenticator integration              | ✅ Implemented |
| **RSA Key Management**          | 2048-bit key generation with 90-day lifecycle               | ✅ Implemented |
| **QR Code Operations**          | Generate and import public keys via QR codes                | ✅ Implemented |
| **Account Management**          | Secure profile and passphrase updates                       | ✅ Implemented |
| **File Encryption**             | Hybrid AES-256-GCM + RSA encryption                         | ✅ Implemented |
| **File Decryption**             | Auto-format detection and secure decryption                 | ✅ Implemented |
| **Digital Signatures**          | SHA-256 + RSA-PSS file signing                              | ✅ Implemented |
| **Signature Verification**      | Multi-key signature validation                              | ✅ Implemented |
| **Role-Based Access**           | Admin and user roles with permissions                       | ✅ Implemented |
| **Security Logging**            | Comprehensive activity audit trails                         | ✅ Implemented |
| **Large File Processing**       | Block-based encryption for files >5MB                       | ✅ Implemented |
| **Key Lifecycle Management**    | Expiration monitoring and renewal alerts                    | ✅ Implemented |
| **Public Key Search**           | Email-based key discovery and management                    | ✅ Implemented |
| **Login Attempt Limits**        | Account lockout protection (5 attempts)                     | ✅ Implemented |
| **Flexible File Formats**       | Combined (.enc) or separate (.enc + .key)                   | ✅ Implemented |
| **Account Recovery**            | Recovery code-based password reset                          | ✅ Implemented |

## 🏗️ Technology Stack

- **Language**: Python 3.8+
- **Database**: SQLite 3 (embedded, no setup required)
- **GUI Framework**: PyQt5
- **Cryptography**: PyCA Cryptography library (RSA-2048, AES-256-GCM, SHA-256)
- **Authentication**: PyOTP for TOTP/OTP generation
- **QR Codes**: QRCode + Pillow for image processing
- **Email Simulation**: SMTP library (console output)

## 📦 Installation

### Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package manager)

### Quick Setup

1. **Clone or extract the project**

   ```bash
   cd SecurityApp
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

**That's it!** The application will automatically:

- Create the SQLite database (`security_app.db`)
- Initialize all required tables
- Create data directories
- Launch the GUI interface

### Dependencies

```
PyQt5>=5.15.0
cryptography>=3.4.8
pyotp>=2.6.0
qrcode[pil]>=7.3.1
Pillow>=8.3.2
mysql-connector-python>=8.0.26
```

## 🚀 Quick Start Guide

### First Time User

1. **Launch Application**

   ```bash
   python main.py
   ```

2. **Register Account**

   - Click "Register New Account"
   - Fill in personal information
   - Create strong passphrase (8+ chars, mixed case, numbers, symbols)
   - **SAVE RECOVERY CODE** (displayed only once!)

3. **Setup Security**

   - Complete MFA setup (OTP or Google Authenticator)
   - Generate RSA key pair for encryption
   - Import contacts' public keys for file sharing

4. **Start Using Features**
   - Encrypt files for secure sharing
   - Sign documents for authenticity
   - Generate QR codes for public key sharing

### Daily Usage

```bash
# Start application
python main.py

# Login flow: Email → Passphrase → MFA Code → Main Interface
```

## 📁 Project Structure

```
SecurityApp/
├── main.py                     # Application entry point
├── requirements.txt            # Python dependencies
├── README.md                  # Project documentation
├── config/
│   └── database.sql           # Database schema definitions
├── modules/                   # Core business logic
│   ├── __init__.py
│   ├── auth.py               # Authentication & user management
│   ├── database_sqlite.py    # SQLite database operations
│   ├── database.py           # MySQL database operations (alternative)
│   ├── mfa.py               # Multi-factor authentication
│   ├── key_manager.py       # RSA key lifecycle management
│   ├── file_crypto.py       # File encryption/decryption
│   ├── digital_signature.py # Digital signing operations
│   ├── qr_handler.py        # QR code generation/reading
│   ├── public_key_manager.py # Public key management
│   ├── key_lifecycle.py     # Key expiration monitoring
│   ├── signature_verification.py # Signature validation
│   └── logger.py            # Security audit logging
├── gui/                      # PyQt5 user interface
│   ├── main_window.py       # Main application window
│   ├── login_screen.py      # Login interface
│   ├── mfa_screen.py        # MFA verification screen
│   ├── main_app_screen.py   # Main dashboard
│   ├── auth/
│   │   └── registration_dialog.py # User registration
│   ├── tabs/                # Feature-specific tabs
│   │   ├── file_operations_tab.py # File encrypt/decrypt
│   │   ├── key_management_tab.py  # RSA key management
│   │   ├── signature_tab.py       # Digital signatures
│   │   ├── qr_operations_tab.py   # QR code operations
│   │   ├── public_keys_tab.py     # Public key management
│   │   ├── account_tab.py         # Account settings
│   │   └── admin_tab.py           # Admin functions
│   ├── controllers/
│   │   └── auth_controller.py     # Authentication logic
│   └── utils/
│       └── dialogs.py             # Common dialog boxes
├── data/                     # Application data storage
│   ├── encrypted/           # Encrypted files output
│   ├── decrypted/          # Decrypted files output
│   ├── qr_codes/           # Generated QR code images
│   └── signatures/         # Digital signature files
├── logs/                    # Security audit logs
│   └── security.log        # Main security event log
├── tests/                   # Test files and scenarios
└── .cursor/rules/          # Comprehensive documentation
    ├── system-architecture.mdc     # Technical architecture
    ├── features-documentation.mdc  # Detailed feature specs
    ├── user-guide.mdc             # Step-by-step usage guide
    ├── execution-flows.mdc        # Implementation details
    ├── implementation-strategy.mdc # Development guidelines
    ├── original-requirements.mdc  # Course requirements
    └── documentation-summary.mdc  # Documentation overview
```

## 📚 Documentation

### Comprehensive Documentation Available

This project includes extensive documentation organized in **Cursor Rules** format:

| Document                                                                 | Purpose                                                  | Audience     |
| ------------------------------------------------------------------------ | -------------------------------------------------------- | ------------ |
| **[System Architecture](.cursor/rules/system-architecture.mdc)**         | Technical overview, database schema, security principles | Developers   |
| **[Features Documentation](.cursor/rules/features-documentation.mdc)**   | Detailed specifications for all 17 features              | Developers   |
| **[User Guide](.cursor/rules/user-guide.mdc)**                           | Step-by-step instructions and troubleshooting            | End Users    |
| **[Execution Flows](.cursor/rules/execution-flows.mdc)**                 | Technical implementation details                         | Developers   |
| **[Implementation Strategy](.cursor/rules/implementation-strategy.mdc)** | Development approach and standards                       | Team         |
| **[Original Requirements](.cursor/rules/original-requirements.mdc)**     | Course project specifications                            | Stakeholders |

### Quick Links

- **Need to understand the system?** → [System Architecture](.cursor/rules/system-architecture.mdc)
- **Want to use the app?** → [User Guide](.cursor/rules/user-guide.mdc)
- **Implementing features?** → [Features Documentation](.cursor/rules/features-documentation.mdc)
- **Development questions?** → [Implementation Strategy](.cursor/rules/implementation-strategy.mdc)

## 🔒 Security Features

### Cryptographic Standards

- **RSA**: 2048-bit keys with OAEP padding
- **AES**: 256-bit keys with GCM mode
- **Hashing**: SHA-256 for all hash operations
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Random Generation**: Cryptographically secure (`secrets` module)

### Security Measures

- **Password Protection**: SHA-256 + unique salt per user
- **Private Key Security**: AES encryption with passphrase-derived keys
- **Session Management**: Secure session tokens with timeout
- **Account Protection**: 5-attempt lockout with 5-minute timeout
- **Audit Trail**: Comprehensive logging of all security events
- **Key Lifecycle**: 90-day expiration with renewal alerts

### Authentication Flow

1. **Credentials**: Email + passphrase verification
2. **MFA Challenge**: 6-digit OTP (5-minute expiry) or TOTP
3. **Session Creation**: Secure session with activity tracking
4. **Role Verification**: User/Admin permissions

## 🎯 Usage Examples

### File Encryption

```
1. Navigate to "File Operations" tab
2. Click "Encrypt File" → Select file
3. Choose recipient from public key list
4. Select output format (combined or separate)
5. File encrypted and saved to data/encrypted/
```

### Digital Signatures

```
1. Navigate to "Signature" tab
2. Click "Sign File" → Select document
3. Enter passphrase → Signature created
4. Share .sig file with document for verification
```

### QR Code Sharing

```
1. Navigate to "QR Operations" tab
2. Click "Generate QR Code" → QR image created
3. Share QR image → Others scan to import your public key
```

## 🛠️ Development

### Development Status

**Status**: ✅ **Complete Implementation**

All 17 required features have been implemented and tested:

- Full GUI interface with PyQt5
- Complete cryptographic operations
- Comprehensive security logging
- Role-based access control
- Account recovery mechanisms

### Testing

```bash
# Run application for testing
python main.py

# Test scenarios available in tests/ directory
# - Sample files for encryption/decryption
# - QR code test images
# - Signature verification samples
```

## 🔧 Troubleshooting

### Common Issues

**Application won't start:**

```bash
# Check Python version
python --version  # Should be 3.8+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**Database errors:**

- SQLite database auto-creates, no manual setup needed
- If corrupted, delete `security_app.db` and restart

**Import errors:**

```bash
# Install missing packages
pip install PyQt5 cryptography pyotp qrcode[pil] pillow
```

**Key/encryption errors:**

- Verify passphrase is correct
- Check if keys have expired (90-day limit)
- Ensure recipient's public key is imported

### Support

- Check [User Guide](.cursor/rules/user-guide.mdc) for detailed instructions
- Review [Troubleshooting section](.cursor/rules/user-guide.mdc#troubleshooting-guide)
- Examine security logs in `logs/security.log`

## 📋 Requirements Compliance

This application fulfills all course requirements:

✅ **17 Core Features** - All implemented and tested  
✅ **GUI Interface** - Complete PyQt5 implementation  
✅ **Security Standards** - Industry-standard cryptography  
✅ **Database Integration** - SQLite with comprehensive schema  
✅ **Documentation** - Extensive technical and user documentation  
✅ **Testing** - Functional testing with sample scenarios

## 📄 License

This is a course project for Computer Security. Educational use only.

---

**Course**: Computer Security  
**Project**: Desktop Security Application  
**Implementation**: Complete (17/17 features)  
**GUI**: PyQt5 with tabbed interface  
**Security**: Industry-standard cryptographic practices
