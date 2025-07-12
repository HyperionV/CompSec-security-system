import sqlite3
from contextlib import contextmanager
import os

class DatabaseManager:
    def __init__(self):
        self.db_path = 'data/security_app.db'
        os.makedirs('data', exist_ok=True)
        print("💾 Using SQLite database for secure storage")
    
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
        """Initialize the database with all required tables"""
        try:
            # Create tables
            self.create_tables()
            
            # Run migrations
            self.run_migrations()
            
            return True
        except Exception as e:
            print(f"Database initialization error: {e}")
            return False
    
    def run_migrations(self):
        """Run database migrations to update schema"""
        try:
            # Check if email column exists in activity_logs table
            check_query = "PRAGMA table_info(activity_logs)"
            columns = self.execute_query(check_query, fetch=True)
            
            has_email_column = False
            if columns:
                for column in columns:
                    if column['name'] == 'email':
                        has_email_column = True
                        break
            
            # Add email column if it doesn't exist
            if not has_email_column:
                alter_query = "ALTER TABLE activity_logs ADD COLUMN email VARCHAR(255)"
                self.execute_query(alter_query)
                print("✓ Added email column to activity_logs table")
                
        except Exception as e:
            print(f"Migration error: {e}")

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
    
    def get_key_by_id(self, key_id):
        """Get specific key by key ID"""
        query = "SELECT * FROM keys WHERE id = ?"
        result = self.execute_query(query, (key_id,), fetch=True)
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
    
    def get_all_user_keys(self, user_id):
        """Get all keys for user (including expired)"""
        query = """
        SELECT id, created_at, expires_at, status
        FROM keys 
        WHERE user_id = ?
        ORDER BY created_at DESC
        """
        return self.execute_query(query, (user_id,), fetch=True)
    
    def update_expired_keys(self):
        """Update status of keys that have passed expiration date"""
        query = """
        UPDATE keys 
        SET status = 'expired' 
        WHERE expires_at <= datetime('now') AND status != 'expired'
        """
        return self.execute_query(query)
    
    def update_expiring_keys(self, warning_days=7):
        """Update status of keys that are approaching expiration"""
        query = """
        UPDATE keys 
        SET status = 'expiring' 
        WHERE expires_at <= datetime('now', '+' || ? || ' days')
        AND expires_at > datetime('now') 
        AND status = 'valid'
        """
        return self.execute_query(query, (warning_days,))
    
    def get_expiring_keys(self, warning_days=7):
        """Get keys that are expiring soon"""
        query = """
        SELECT k.*, u.email, u.name
        FROM keys k
        JOIN users u ON k.user_id = u.id
        WHERE k.expires_at <= datetime('now', '+' || ? || ' days')
        AND k.expires_at > datetime('now')
        AND k.status IN ('valid', 'expiring')
        ORDER BY k.expires_at ASC
        """
        return self.execute_query(query, (warning_days,), fetch=True)
    
    def get_expired_keys(self):
        """Get keys that have expired"""
        query = """
        SELECT k.*, u.email, u.name
        FROM keys k
        JOIN users u ON k.user_id = u.id
        WHERE k.expires_at <= datetime('now')
        AND k.status != 'expired'
        ORDER BY k.expires_at ASC
        """
        return self.execute_query(query, fetch=True)

    # OTP Management Operations
    
    def store_otp(self, user_id, otp_code, expires_at):
        """Store OTP code for user"""
        query = """
        INSERT INTO otp_codes (user_id, otp_code, expires_at)
        VALUES (?, ?, ?)
        """
        return self.execute_query(query, (user_id, otp_code, expires_at))
    
    def get_valid_otp(self, user_id, otp_code):
        """Get valid OTP for user"""
        query = """
        SELECT id, otp_code, expires_at 
        FROM otp_codes 
        WHERE user_id = ? AND otp_code = ? AND used = 0 AND expires_at > datetime('now')
        ORDER BY created_at DESC
        LIMIT 1
        """
        result = self.execute_query(query, (user_id, otp_code), fetch=True)
        return result[0] if result else None
    
    def mark_otp_used(self, otp_id):
        """Mark OTP as used"""
        query = "UPDATE otp_codes SET used = 1 WHERE id = ?"
        return self.execute_query(query, (otp_id,))
    
    def cleanup_expired_otps(self):
        """Remove expired OTP codes"""
        query = "DELETE FROM otp_codes WHERE expires_at < datetime('now')"
        return self.execute_query(query)

    # Activity Logging Operations
    
    def log_activity(self, user_id, action, status, details, ip_address='127.0.0.1'):
        """Log security activity"""
        query = """
        INSERT INTO activity_logs (user_id, action, status, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """
        return self.execute_query(query, (user_id, action, status, details, ip_address))
    
    def get_user_activity_logs(self, user_id, limit=100):
        """Get activity logs for specific user"""
        query = """
        SELECT * FROM activity_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
        """
        return self.execute_query(query, (user_id, limit), fetch=True)
    
    def get_all_activity_logs(self, limit=100):
        """Get all activity logs (admin function)"""
        query = """
        SELECT al.*, u.email, u.name
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC 
        LIMIT ?
        """
        return self.execute_query(query, (limit,), fetch=True)

    # Public Key Management Operations
    
    def import_public_key(self, owner_email, public_key, creation_date, imported_by):
        """Import a public key from QR code"""
        # SQLite doesn't support ON DUPLICATE KEY UPDATE, so use INSERT OR REPLACE
        query = """
        INSERT OR REPLACE INTO public_keys (owner_email, public_key, creation_date, imported_by, imported_at, is_active)
        VALUES (?, ?, ?, ?, datetime('now'), 1)
        """
        return self.execute_query(query, (owner_email, public_key, creation_date, imported_by))
    
    def get_public_keys_by_user(self, user_id):
        """Get all public keys imported by a user"""
        query = """
        SELECT * FROM public_keys 
        WHERE imported_by = ? AND is_active = 1
        ORDER BY imported_at DESC
        """
        return self.execute_query(query, (user_id,), fetch=True)
    
    def search_public_key_by_email(self, user_id, email):
        """Search for a public key by email"""
        query = """
        SELECT * FROM public_keys 
        WHERE imported_by = ? AND owner_email = ? AND is_active = 1
        ORDER BY imported_at DESC
        LIMIT 1
        """
        result = self.execute_query(query, (user_id, email), fetch=True)
        return result[0] if result else None
    
    def deactivate_public_key(self, key_id, user_id):
        """Deactivate a public key"""
        query = """
        UPDATE public_keys 
        SET is_active = 0 
        WHERE id = ? AND imported_by = ?
        """
        return self.execute_query(query, (key_id, user_id))
    
    def get_public_key_by_id(self, key_id, user_id):
        """Get specific public key by ID"""
        query = """
        SELECT * FROM public_keys 
        WHERE id = ? AND imported_by = ? AND is_active = 1
        """
        result = self.execute_query(query, (key_id, user_id), fetch=True)
        return result[0] if result else None

    def get_all_imported_public_keys(self, user_email):
        user_id = self.get_user_id(user_email)
        if not user_id:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, email, public_key, created_at 
                FROM public_keys 
                WHERE user_id = ? AND is_active = 1
                ORDER BY created_at DESC
            """, (user_id,))
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Database error getting imported public keys: {e}")
            return []

    def search_public_keys_by_email(self, search_email):
        """Search for public keys by email address with pattern matching"""
        query = """
        SELECT pk.id, pk.owner_email, pk.public_key, pk.creation_date, pk.imported_by, pk.is_active,
               u.email as importer_email
        FROM public_keys pk
        LEFT JOIN users u ON pk.imported_by = u.id
        WHERE pk.owner_email LIKE ? AND pk.is_active = 1
        ORDER BY pk.creation_date DESC
        """
        search_pattern = f"%{search_email}%"
        return self.execute_query(query, (search_pattern,), fetch=True)

    # Admin Panel Operations

    def get_all_users_for_admin(self):
        """Get all users for admin management (excluding sensitive data)"""
        query = """
        SELECT id, email, name, phone, address, birth_date, role, 
               is_locked, failed_attempts, locked_until, created_at
        FROM users 
        ORDER BY created_at DESC
        """
        return self.execute_query(query, fetch=True)

    def get_user_details_for_admin(self, user_id):
        """Get detailed user information for admin management"""
        query = """
        SELECT id, email, name, phone, address, birth_date, role, 
               is_locked, failed_attempts, locked_until, created_at
        FROM users 
        WHERE id = ?
        """
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0] if result else None

    def admin_lock_user_account(self, user_id, admin_user_id):
        """Lock user account (admin action)"""
        query = "UPDATE users SET is_locked = 1 WHERE id = ?"
        result = self.execute_query(query, (user_id,))
        
        # Log admin action
        if result:
            self.log_activity(
                admin_user_id, 
                'admin_lock_account', 
                'success', 
                f'Admin locked user account ID: {user_id}'
            )
        return result

    def admin_unlock_user_account(self, user_id, admin_user_id):
        """Unlock user account and reset failed attempts (admin action)"""
        query = """
        UPDATE users 
        SET is_locked = 0, failed_attempts = 0, locked_until = NULL 
        WHERE id = ?
        """
        result = self.execute_query(query, (user_id,))
        
        # Log admin action
        if result:
            self.log_activity(
                admin_user_id, 
                'admin_unlock_account', 
                'success', 
                f'Admin unlocked user account ID: {user_id}'
            )
        return result

    def get_system_statistics(self):
        """Get system-wide statistics for admin dashboard"""
        stats = {}
        
        # Total users
        query = "SELECT COUNT(*) as total_users FROM users"
        result = self.execute_query(query, fetch=True)
        stats['total_users'] = result[0]['total_users'] if result else 0
        
        # Admin users
        query = "SELECT COUNT(*) as admin_users FROM users WHERE role = 'admin'"
        result = self.execute_query(query, fetch=True)
        stats['admin_users'] = result[0]['admin_users'] if result else 0
        
        # Locked accounts
        query = "SELECT COUNT(*) as locked_accounts FROM users WHERE is_locked = 1"
        result = self.execute_query(query, fetch=True)
        stats['locked_accounts'] = result[0]['locked_accounts'] if result else 0
        
        # Total RSA key pairs
        query = "SELECT COUNT(*) as total_keys FROM keys"
        result = self.execute_query(query, fetch=True)
        stats['total_keys'] = result[0]['total_keys'] if result else 0
        
        # Valid keys
        query = "SELECT COUNT(*) as valid_keys FROM keys WHERE status = 'valid'"
        result = self.execute_query(query, fetch=True)
        stats['valid_keys'] = result[0]['valid_keys'] if result else 0
        
        # Expired keys
        query = "SELECT COUNT(*) as expired_keys FROM keys WHERE status = 'expired'"
        result = self.execute_query(query, fetch=True)
        stats['expired_keys'] = result[0]['expired_keys'] if result else 0
        
        # Imported public keys
        query = "SELECT COUNT(*) as imported_keys FROM public_keys WHERE is_active = 1"
        result = self.execute_query(query, fetch=True)
        stats['imported_keys'] = result[0]['imported_keys'] if result else 0
        
        # Recent registrations (last 30 days)
        query = """
        SELECT COUNT(*) as recent_registrations 
        FROM users 
        WHERE created_at >= datetime('now', '-30 days')
        """
        result = self.execute_query(query, fetch=True)
        stats['recent_registrations'] = result[0]['recent_registrations'] if result else 0
        
        return stats

    def get_system_activity_logs(self, limit=100, offset=0, user_filter=None, action_filter=None):
        """Get system activity logs with optional filtering"""
        query = "SELECT * FROM activity_logs"
        params = []
        
        # Apply filters if provided
        where_clauses = []
        if user_filter:
            where_clauses.append("user_id = ?")
            params.append(user_filter)
        if action_filter:
            where_clauses.append("action LIKE ?")
            params.append(f"%{action_filter}%")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        return self.execute_query(query, params, fetch=True)
    
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
    
    def get_user_role(self, user_id):
        """Get user role by ID"""
        query = "SELECT role FROM users WHERE id = ?"
        result = self.execute_query(query, (user_id,), fetch=True)
        return result[0]['role'] if result else None

    def update_user_role(self, user_id, new_role, admin_user_id):
        """Update user role (admin action)"""
        if new_role not in ['admin', 'user']:
            return False
        
        query = "UPDATE users SET role = ? WHERE id = ?"
        result = self.execute_query(query, (new_role, user_id))
        
        # Log admin action
        if result:
            self.log_activity(
                admin_user_id, 
                'admin_update_role', 
                'success', 
                f'Admin changed role for user ID {user_id} to {new_role}'
            )
        return result

    def admin_delete_user_account(self, user_id, admin_user_id):
        """Delete user account (admin action) - use with extreme caution"""
        # Get user email for logging
        user_query = "SELECT email FROM users WHERE id = ?"
        user_result = self.execute_query(user_query, (user_id,), fetch=True)
        user_email = user_result[0]['email'] if user_result else 'Unknown'
        
        # Delete user (will cascade to related records)
        query = "DELETE FROM users WHERE id = ?"
        result = self.execute_query(query, (user_id,))
        
        # Log admin action
        if result:
            self.log_activity(
                admin_user_id, 
                'admin_delete_account', 
                'success', 
                f'Admin deleted user account: {user_email} (ID: {user_id})'
            )
        return result

    def create_tables(self):
        """Create all required database tables"""
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
                role TEXT DEFAULT 'user',
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
                status TEXT DEFAULT 'valid',
                FOREIGN KEY (user_id) REFERENCES users(id)
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
                FOREIGN KEY (user_id) REFERENCES users(id)
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
                FOREIGN KEY (user_id) REFERENCES users(id)
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
                FOREIGN KEY (imported_by) REFERENCES users(id)
            )
            """)
            
            # Activity logs table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_id ON activity_logs(user_id)")
            
            conn.commit()
        print("✅ SQLite database initialized successfully!")

# Global database instance
db = DatabaseManager() 