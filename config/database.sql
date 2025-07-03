-- Security Application Database Schema
CREATE DATABASE IF NOT EXISTS security_app;
USE security_app;

-- Users table with comprehensive security features
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    birth_date DATE,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    recovery_code_hash VARCHAR(64)
);

-- RSA Keys table with expiration management
CREATE TABLE keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    status ENUM('valid', 'expiring', 'expired') DEFAULT 'valid',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- OTP codes for multi-factor authentication
CREATE TABLE otp_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Recovery codes for account recovery
CREATE TABLE recovery_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    recovery_code_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Public keys imported from QR codes for file encryption
CREATE TABLE public_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    owner_email VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    creation_date DATE NOT NULL,
    imported_by INT NOT NULL,
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (imported_by) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_email_owner (owner_email, imported_by)
);

-- Activity logs for security monitoring
CREATE TABLE activity_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    status ENUM('success', 'failure', 'warning') NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_keys_user_id ON keys(user_id);
CREATE INDEX idx_keys_status ON keys(status);
CREATE INDEX idx_otp_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_expires ON otp_codes(expires_at);
CREATE INDEX idx_logs_user_id ON activity_logs(user_id);
CREATE INDEX idx_logs_timestamp ON activity_logs(timestamp);
CREATE INDEX idx_pubkeys_imported_by ON public_keys(imported_by);
CREATE INDEX idx_pubkeys_owner_email ON public_keys(owner_email);

-- Create default admin user (password: admin123, salt will be generated)
-- This will be updated with proper hash in the application
INSERT INTO users (email, name, password_hash, salt, role) VALUES 
('admin@security.app', 'System Administrator', 'temp_hash', 'temp_salt', 'admin'); 