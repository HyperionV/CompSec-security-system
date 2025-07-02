"""
SecurityApp Configuration Settings
"""

# Database Configuration
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '',  # Set your MySQL password here
    'database': 'security_app',
    'charset': 'utf8mb4',
    'autocommit': True
}

# Security Configuration
SECURITY_CONFIG = {
    'password_min_length': 8,
    'salt_length': 32,
    'rsa_key_size': 2048,
    'key_expiry_days': 90,
    'otp_expiry_minutes': 5,
    'max_failed_attempts': 5,
    'lockout_duration_minutes': 5
}

# File Configuration
FILE_CONFIG = {
    'large_file_threshold': 5 * 1024 * 1024,  # 5MB
    'block_size': 1024 * 1024,  # 1MB
    'qr_code_size': 256,
    'data_directory': './data',
    'log_directory': './logs'
} 