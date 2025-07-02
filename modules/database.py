import mysql.connector
from mysql.connector import Error
from config.config import DATABASE_CONFIG
from modules.logger import log_database_event, log_error

class DatabaseManager:
    def __init__(self):
        self.connection = None
        
    def connect(self):
        try:
            self.connection = mysql.connector.connect(**DATABASE_CONFIG)
            log_database_event('SUCCESS', f"Connected to database: {DATABASE_CONFIG['database']}")
            return True
        except Error as e:
            log_database_event('FAILED', f"Database connection error: {str(e)}")
            print(f"Database connection error: {e}")
            return False
    
    def disconnect(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def execute_query(self, query, params=None, fetch=False):
        if not self.connection or not self.connection.is_connected():
            if not self.connect():
                return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params or ())
            
            if fetch:
                result = cursor.fetchall()
                cursor.close()
                return result
            else:
                self.connection.commit()
                cursor.close()
                return True
                
        except Error as e:
            print(f"Database query error: {e}")
            return None
    
    def create_tables(self):
        queries = [
            """CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(20),
                address TEXT,
                birth_date DATE,
                password_hash BINARY(32) NOT NULL,
                salt BINARY(32) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_locked BOOLEAN DEFAULT FALSE,
                failed_attempts INT DEFAULT 0,
                locked_until TIMESTAMP NULL,
                recovery_code_hash VARCHAR(64),
                totp_secret VARCHAR(255)
            )""",
            
            """CREATE TABLE IF NOT EXISTS `keys` (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                public_key TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                status ENUM('valid', 'expiring', 'expired') DEFAULT 'valid',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""",
            
            """CREATE TABLE IF NOT EXISTS otp_codes (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                otp_code VARCHAR(6) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"""
        ]
        
        for query in queries:
            self.execute_query(query)
    
    def create_user(self, email, name, password_hash, salt, phone=None, address=None, birth_date=None):
        query = """INSERT INTO users (email, name, password_hash, salt, phone, address, birth_date) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)"""
        params = (email, name, password_hash, salt, phone, address, birth_date)
        return self.execute_query(query, params)
    
    def user_exists(self, email):
        query = "SELECT id FROM users WHERE email = %s"
        result = self.execute_query(query, (email,), fetch=True)
        return result is not None and len(result) > 0
    
    def get_user(self, email):
        query = "SELECT * FROM users WHERE email = %s"
        result = self.execute_query(query, (email,), fetch=True)
        return result[0] if result else None
    
    def get_user_by_email(self, email):
        return self.get_user(email)

    def create_otp_code(self, user_id, otp_code, expires_at):
        try:
            cursor = self.connection.cursor()
            query = """
                INSERT INTO otp_codes (user_id, otp_code, created_at, expires_at, used)
                VALUES (%s, %s, NOW(), %s, FALSE)
            """
            cursor.execute(query, (user_id, otp_code, expires_at))
            self.connection.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"Error creating OTP code: {e}")
            return False

    def validate_otp_code(self, user_id, otp_code):
        try:
            cursor = self.connection.cursor()
            
            # First cleanup expired OTPs
            cleanup_query = "DELETE FROM otp_codes WHERE expires_at < NOW() OR used = TRUE"
            cursor.execute(cleanup_query)
            
            # Check for valid OTP
            query = """
                SELECT id FROM otp_codes 
                WHERE user_id = %s AND otp_code = %s AND expires_at > NOW() AND used = FALSE
            """
            cursor.execute(query, (user_id, otp_code))
            result = cursor.fetchone()
            
            if result:
                # Mark OTP as used
                update_query = "UPDATE otp_codes SET used = TRUE WHERE id = %s"
                cursor.execute(update_query, (result[0],))
                self.connection.commit()
                cursor.close()
                return True
            
            self.connection.commit()
            cursor.close()
            return False
        except Exception as e:
            print(f"Error validating OTP: {e}")
            return False

    def cleanup_expired_otps(self):
        try:
            cursor = self.connection.cursor()
            query = "DELETE FROM otp_codes WHERE expires_at < NOW() OR used = TRUE"
            cursor.execute(query)
            deleted_count = cursor.rowcount
            self.connection.commit()
            cursor.close()
            return deleted_count
        except Exception as e:
            print(f"Error cleaning up expired OTPs: {e}")
            return 0

    def get_user_by_id(self, user_id):
        try:
            cursor = self.connection.cursor()
            query = "SELECT id, email, name, role FROM users WHERE id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return {
                    'id': result[0],
                    'email': result[1],
                    'name': result[2],
                    'role': result[3]
                }
            return None
        except Exception as e:
            print(f"Error fetching user by ID: {e}")
            return None

    def update_user_totp_secret(self, user_id, totp_secret):
        try:
            cursor = self.connection.cursor()
            query = "UPDATE users SET totp_secret = %s WHERE id = %s"
            cursor.execute(query, (totp_secret, user_id))
            affected_rows = cursor.rowcount
            self.connection.commit()
            cursor.close()
            return affected_rows > 0
        except Exception as e:
            print(f"Error updating TOTP secret: {e}")
            return False

    def get_user_totp_secret(self, user_id):
        try:
            cursor = self.connection.cursor()
            query = "SELECT totp_secret FROM users WHERE id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result and result[0] else None
        except Exception as e:
            print(f"Error fetching TOTP secret: {e}")
            return None

db_manager = DatabaseManager() 