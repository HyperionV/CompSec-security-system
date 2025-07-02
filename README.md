# SecurityApp

A comprehensive desktop security application built with Python, MySQL, and PyQt5.

## Features

- User authentication with multi-factor authentication (OTP/TOTP)
- RSA/AES encryption for file operations
- Digital signatures and verification
- QR code key sharing
- Role-based access control
- Account management and recovery

## Requirements

- Python 3.8+
- MySQL 5.7+
- See `requirements.txt` for Python dependencies

## Installation

1. Clone the repository
2. Install Python dependencies: `pip install -r requirements.txt`
3. Set up MySQL database using `config/database.sql`
4. Configure database connection in `config/config.py`
5. Run the application: `python main.py`

## Project Structure

```
SecurityApp/
├── main.py                 # Application entry point
├── modules/                # Core functionality modules
├── gui/                    # GUI components
├── data/                   # Data storage
│   ├── test_files/         # Test files
│   ├── qr_codes/          # QR code images
│   └── signatures/         # Digital signature files
├── config/                 # Configuration files
├── logs/                   # Application logs
└── README.md              # This file
```

## License

This project is for educational purposes.
