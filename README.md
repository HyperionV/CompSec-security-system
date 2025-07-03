# Security Application

A comprehensive desktop security application implementing 17 core security functionalities including user management, multi-factor authentication, RSA key management, file encryption/decryption, digital signatures, and role-based access control.

## Features

### Core Security Features (17 Functionalities)

1. **User Registration** - Secure registration with email validation and password strength checking
2. **Multi-Factor Authentication** - OTP/TOTP with Google Authenticator integration
3. **RSA Key Management** - 2048-bit key generation with 90-day expiration
4. **QR Code Public Key Sharing** - Generate and read QR codes for key distribution
5. **Account Updates** - Secure profile and passphrase management
6. **File Encryption** - Hybrid AES+RSA encryption for files
7. **File Decryption** - Secure file decryption with format auto-detection
8. **Digital Signatures** - RSA-based file signing
9. **Signature Verification** - Multi-key signature validation
10. **Role-Based Access Control** - Admin and user roles with permissions
11. **Security Logging** - Comprehensive activity monitoring
12. **Large File Handling** - Block-based encryption for files >5MB
13. **Key Status Management** - Expiration monitoring and renewal
14. **Public Key Search** - Email-based key lookup
15. **Login Attempt Limiting** - 5-attempt lockout with timeout
16. **Flexible File Formats** - Combined or separate encryption files
17. **Account Recovery** - Recovery code-based password reset

## Technology Stack

- **Language**: Python 3.8+
- **Database**: MySQL 8.0+
- **GUI Framework**: PyQt5
- **Cryptography**: PyCA Cryptography library
- **OTP**: PyOTP library
- **QR Codes**: QRCode library

## Installation

### Prerequisites

1. **Python 3.8 or higher**
2. **MySQL Server 8.0 or higher**

### Setup Steps

1. **Clone or extract the project**

   ```bash
   cd SecurityApp
   ```

2. **Install Python dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure MySQL**

   - Ensure MySQL server is running
   - Update database credentials in `modules/database.py` if needed
   - Default configuration uses:
     - Host: localhost
     - User: root
     - Password: (empty)
     - Database: security_app (will be created automatically)

4. **Initialize the application**
   ```bash
   python main.py
   ```

### Database Setup

The application will automatically create the required database and tables on first run. The database schema includes:

- `users` - User accounts with security features
- `keys` - RSA key pairs with expiration management
- `otp_codes` - Multi-factor authentication codes
- `recovery_codes` - Account recovery tokens
- `activity_logs` - Security event logging

## Project Structure

```
SecurityApp/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── modules/               # Core functionality modules
│   ├── __init__.py
│   ├── database.py        # Database operations
│   └── logger.py          # Security logging
├── gui/                   # PyQt5 user interface (to be implemented)
├── config/                # Configuration files
│   └── database.sql       # Database schema
├── data/                  # Data storage
│   ├── test_files/        # Test files for encryption
│   ├── qr_codes/          # Generated QR codes
│   └── signatures/        # Digital signature files
└── logs/                  # Security log files
    └── security.log       # Main security log
```

## Usage

### Initial Setup

1. Run the application to initialize the database
2. Register user accounts through the interface
3. Generate RSA key pairs for encryption/decryption
4. Configure multi-factor authentication

### Security Features

- All passwords are hashed using SHA-256 with unique salts
- Private keys are encrypted with AES using passphrase-derived keys
- Comprehensive logging of all security events
- Automatic account lockout after failed login attempts
- Key expiration management with renewal notifications

## Development Status

**Current Phase**: Foundation Setup Complete ✓

- Database schema implemented
- Security logging system active
- Core modules structured

**Next Phases**:

- User registration and authentication
- RSA key management
- File encryption/decryption
- GUI development

## Security Considerations

- Never store passwords in plain text
- Private keys are always encrypted before storage
- All cryptographic operations use secure libraries
- Comprehensive audit logging for security events
- Regular key rotation recommended

## Troubleshooting

### Database Connection Issues

- Verify MySQL server is running
- Check credentials in `modules/database.py`
- Ensure MySQL user has appropriate permissions

### Dependencies Issues

- Ensure Python 3.8+ is installed
- Run `pip install -r requirements.txt` again
- Check for conflicting package versions

## License

This is a course project for Computer Security course.
