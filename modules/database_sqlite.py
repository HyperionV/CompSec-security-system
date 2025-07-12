import sqlite3
from contextlib import contextmanager
import os
from datetime import datetime, timedelta

class SQLiteDatabaseManager:
    def __init__(self, db_path='data/security_app.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.initialize_database()
    
    @contextmanager
    def get_connection(self):
        connection = None
        try:
            connection = sqlite3.connect(self.db_path)
            connection.row_factory = sqlite3.Row  # Enable dict-like access
            yield connection
        except Exception as e:
            if connection:
                connection.rollback()
            raise e
        finally:
            if connection:
                connection.close()
    
    def execute_query(self, query, params=None, fetch=False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            
            if fetch:
                result = cursor.fetchall()
                return [dict(row) for row in result]
            else:
                conn.commit()
                return cursor.lastrowid if cursor.lastrowid else cursor.rowcount
    
    def execute_many(self, query, data_list):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, data_list)
            conn.commit()
            return cursor.rowcount
    
    def get_user_by_email(self, email):
        query = "SELECT * FROM users WHERE email = ?"
        result = self.execute_query(query, (email,), fetch=True)
        return result[0] if result else None
    
    def get_user_by_id(self, user_id):
        query = "SELECT * FROM users WHERE id = ?"
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0] if result else None
    
    def create_user(self, email, name, phone, address, birth_date, password_hash, salt, recovery_code_hash=None):
        query = """
        INSERT INTO users (email, name, phone, address, birth_date, password_hash, salt, recovery_code_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (email, name, phone, address, birth_date, password_hash, salt, recovery_code_hash)
        return self.execute_query(query, params)
    
    def update_failed_attempts(self, user_id, attempts, locked_until=None):
        query = "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?"
        return self.execute_query(query, (attempts, locked_until, user_id))
    
    def unlock_account(self, user_id):
        query = "UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?"
        return self.execute_query(query, (user_id,))
    
    def update_user_info(self, user_id, name=None, phone=None, address=None, birth_date=None):
        """Update user profile information"""
        fields = []
        params = []
        
        if name is not None:
            fields.append("name = ?")
            params.append(name)
        if phone is not None:
            fields.append("phone = ?")
            params.append(phone)
        if address is not None:
            fields.append("address = ?")
            params.append(address)
        if birth_date is not None:
            fields.append("birth_date = ?")
            params.append(birth_date)
        
        if fields:
            query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
            params.append(user_id)
            return self.execute_query(query, params)
        return 0
    
    def update_password(self, user_id, password_hash, salt):
        """Update user password and salt"""
        query = "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?"
        return self.execute_query(query, (password_hash, salt, user_id))
    
    def create_recovery_code(self, user_id, recovery_code_hash):
        """Store recovery code for user"""
        query = "INSERT INTO recovery_codes (user_id, recovery_code_hash) VALUES (?, ?)"
        return self.execute_query(query, (user_id, recovery_code_hash))
    
    def verify_recovery_code(self, user_id, recovery_code_hash):
        """Verify recovery code and mark as used"""
        # Check if recovery code exists and hasn't been used
        query = "SELECT id FROM recovery_codes WHERE user_id = ? AND recovery_code_hash = ? AND used_at IS NULL"
        result = self.execute_query(query, (user_id, recovery_code_hash), fetch=True)
        
        if result:
            # Mark recovery code as used
            update_query = "UPDATE recovery_codes SET used_at = datetime('now') WHERE id = ?"
            self.execute_query(update_query, (result[0]['id'],))
            return True
        return False
    
    def initialize_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    phone TEXT,
                    address TEXT,
                    birth_date TEXT,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_locked INTEGER DEFAULT 0,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    recovery_code_hash TEXT
                )
                """)
                
                # Keys table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    public_key TEXT NOT NULL,
                    encrypted_private_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'valid' CHECK(status IN ('valid', 'expiring', 'expired')),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """)
                
                # OTP codes table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    otp_code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    used INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """)
                
                # TOTP secrets table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS totp_secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """)
                
                # Recovery codes table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    recovery_code_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    used_at TIMESTAMP NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """)
                
                # Public keys table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS public_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_email TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    creation_date TEXT NOT NULL,
                    imported_by INTEGER NOT NULL,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (imported_by) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(owner_email, imported_by)
                )
                """)
                
                # Activity logs table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('success', 'failure', 'warning')),
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )
                """)
                
                # Create indexes
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_id ON activity_logs(user_id)")
                
                conn.commit()
            return True
        except Exception as e:
            print(f"SQLite database initialization failed: {e}")
            return False

    # Key Management Operations
    def store_user_keys(self, user_id, public_key_pem, encrypted_private_key_json, created_at, expires_at):
        """Store RSA key pair for user"""
        query = """
        INSERT INTO keys (user_id, public_key, encrypted_private_key, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        return self.execute_query(query, (user_id, public_key_pem, encrypted_private_key_json, created_at, expires_at, 'valid'))
    
    def get_user_keys_by_id(self, user_id):
        """Get current valid keys for user"""
        query = """
        SELECT id, public_key, encrypted_private_key, created_at, expires_at, status
        FROM keys 
        WHERE user_id = ? AND status IN ('valid', 'expiring')
        ORDER BY created_at DESC
        LIMIT 1
        """
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0] if result else None
    
    def update_key_status(self, key_id, status):
        """Update key status"""
        query = "UPDATE keys SET status = ? WHERE id = ?"
        return self.execute_query(query, (status, key_id))

    def update_key_encrypted_private_key(self, key_id: int, encrypted_private_key_json: str) -> int:
        """Update the encrypted private key for a given key ID"""
        query = "UPDATE keys SET encrypted_private_key = ? WHERE id = ?"
        return self.execute_query(query, (encrypted_private_key_json, key_id))
    
    def expire_user_keys(self, user_id):
        """Mark all user keys as expired"""
        query = "UPDATE keys SET status = 'expired' WHERE user_id = ? AND status IN ('valid', 'expiring')"
        return self.execute_query(query, (user_id,))
    
    # Activity logging
    def log_activity(self, user_id, action, status, details, ip_address='127.0.0.1'):
        """Log user activity"""
        query = """
        INSERT INTO activity_logs (user_id, action, status, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """
        return self.execute_query(query, (user_id, action, status, details, ip_address))
    
    # Additional methods for compatibility with MySQL version
    def search_public_keys_by_email(self, search_email):
        """Search for public keys by email"""
        query = """
        SELECT id, owner_email, public_key, creation_date, imported_by, imported_at
        FROM public_keys 
        WHERE owner_email LIKE ? AND is_active = 1
        ORDER BY imported_at DESC
        """
        return self.execute_query(query, (f'%{search_email}%',), fetch=True)
    
    def import_public_key(self, owner_email, public_key, creation_date, imported_by):
        """Import a public key from QR code"""
        query = """
        INSERT INTO public_keys (owner_email, public_key, creation_date, imported_by)
        VALUES (?, ?, ?, ?)
        """
        return self.execute_query(query, (owner_email, public_key, creation_date, imported_by))
    
    def get_all_users_for_admin(self):
        """Get all users for admin panel"""
        query = """
        SELECT id, email, name, role, created_at, is_locked, failed_attempts
        FROM users 
        ORDER BY created_at DESC
        """
        return self.execute_query(query, fetch=True)
    
    def store_otp(self, user_id, otp_code, expires_at):
        """Store OTP code"""
        query = "INSERT INTO otp_codes (user_id, otp_code, expires_at) VALUES (?, ?, ?)"
        return self.execute_query(query, (user_id, otp_code, expires_at))
    
    def get_valid_otp(self, user_id, otp_code):
        """Get valid OTP for user"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        query = """
        SELECT * FROM otp_codes 
        WHERE user_id = ? AND otp_code = ? AND expires_at > ? AND used = 0
        """
        result = self.execute_query(query, (user_id, otp_code, current_time), fetch=True)
        return result[0] if result else None
    
    def store_totp_secret(self, user_id, secret):
        """Store TOTP secret for user"""
        query = """
        INSERT OR REPLACE INTO totp_secrets (user_id, secret)
        VALUES (?, ?)
        """
        return self.execute_query(query, (user_id, secret))
    
    def get_totp_secret(self, user_id):
        """Get TOTP secret for user"""
        query = """
        SELECT secret FROM totp_secrets 
        WHERE user_id = ? AND is_active = 1
        """
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0]['secret'] if result else None
    
    def has_totp_setup(self, user_id):
        """Check if user has TOTP setup"""
        query = """
        SELECT COUNT(*) as count FROM totp_secrets 
        WHERE user_id = ? AND is_active = 1
        """
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0]['count'] > 0 if result else False
        
    def get_user_id(self, email):
        """Get user ID from email address"""
        query = "SELECT id FROM users WHERE email = ?"
        result = self.execute_query(query, (email,), fetch=True)
        return result[0]['id'] if result else None
        
    def get_user_public_key(self, user_id):
        """Get the latest valid public key for a user"""
        query = """
        SELECT public_key FROM keys 
        WHERE user_id = ? AND status IN ('valid', 'expiring') 
        ORDER BY created_at DESC 
        LIMIT 1
        """
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0]['public_key'] if result else None
        
    def get_all_public_keys(self):
        """Get all imported public keys"""
        query = """
        SELECT owner_email as email, public_key 
        FROM public_keys 
        WHERE is_active = 1
        """
        return self.execute_query(query, fetch=True) 