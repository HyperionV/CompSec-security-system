import os
import secrets
import base64
import json
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, Union

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .database import db
from .logger import security_logger

# Utility functions for safe datetime handling
def safe_to_datetime(dt_value):
    """Convert string or datetime to datetime object safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, datetime):
        return dt_value
    if isinstance(dt_value, str):
        return datetime.fromisoformat(dt_value)
    return datetime.fromisoformat(str(dt_value))

def safe_to_isoformat(dt_value):
    """Convert string or datetime to ISO format string safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, str):
        return dt_value  # Already a string
    if hasattr(dt_value, 'isoformat'):
        return dt_value.isoformat()
    return str(dt_value)  # fallback to string conversion

class KeyManager:
    def __init__(self):
        self.key_size = 2048
        self.public_exponent = 65537
        self.key_expiry_days = 90
        self.warning_days = 7
        self.pbkdf2_iterations = 200000
        self.aes_key_length = 32  # 256 bits
        self.nonce_length = 12   # 96 bits for GCM
        self.salt_length = 16    # 128 bits
    
    def generate_rsa_keypair(self) -> Tuple[bool, str, Optional[Dict]]:
        """Generate 2048-bit RSA key pair with proper entropy"""
        try:
            # Generate RSA private key using cryptographically secure entropy
            private_key = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.key_size,
                backend=default_backend()
            )
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Serialize public key (SubjectPublicKeyInfo format)
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Return private key object and public key PEM
            result = {
                'private_key': private_key,
                'public_key_pem': public_key_pem,
                'key_size': self.key_size,
                'public_exponent': self.public_exponent
            }
            
            security_logger.log_activity(
                action='rsa_keypair_generation',
                status='success',
                details=f'Generated {self.key_size}-bit RSA key pair'
            )
            
            return True, "RSA key pair generated successfully", result
            
        except Exception as e:
            security_logger.log_activity(
                action='rsa_keypair_generation',
                status='failure',
                details=f'Key generation failed: {str(e)}'
            )
            return False, f"Key generation failed: {str(e)}", None
    
    def encrypt_private_key(self, private_key, passphrase: str) -> Tuple[bool, str, Optional[Dict]]:
        """Encrypt private key using AES-256-GCM with PBKDF2-derived key"""
        try:
            # Generate random salt and nonce
            salt = secrets.token_bytes(self.salt_length)
            nonce = secrets.token_bytes(self.nonce_length)
            
            # Derive AES key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.aes_key_length,
                salt=salt,
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            aes_key = kdf.derive(passphrase.encode('utf-8'))
            
            # Serialize private key to DER format for encryption
            private_key_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Encrypt using AES-256-GCM
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, private_key_der, None)
            
            # Encode binary data to base64 for storage
            encrypted_data = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'algorithm': 'AES-256-GCM',
                'kdf': 'PBKDF2-SHA256',
                'iterations': self.pbkdf2_iterations
            }
            
            security_logger.log_activity(
                action='private_key_encryption',
                status='success',
                details='Private key encrypted with AES-256-GCM'
            )
            
            return True, "Private key encrypted successfully", encrypted_data
            
        except Exception as e:
            security_logger.log_activity(
                action='private_key_encryption',
                status='failure',
                details=f'Private key encryption failed: {str(e)}'
            )
            return False, f"Private key encryption failed: {str(e)}", None
    
    def decrypt_private_key(self, encrypted_data: Dict, passphrase: str) -> Tuple[bool, str, Optional[object]]:
        """Decrypt private key using stored encryption parameters"""
        try:
            # Decode base64 data
            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])

            # Add debug info about the passphrase (safely)
            print(f"DEBUG: Passphrase in decrypt_private_key - length: {len(passphrase)}")
            print(f"DEBUG: First character: '{passphrase[0]}', Last character: '{passphrase[-1]}'")
            if len(passphrase) > 2:
                print(f"DEBUG: Second character: '{passphrase[1]}', Second-to-last character: '{passphrase[-2]}'")

            # Derive AES key using stored parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.aes_key_length,
                salt=salt,
                iterations=encrypted_data['iterations'],
                backend=default_backend()
            )
            aes_key = kdf.derive(passphrase.encode('utf-8'))

            print(f"DEBUG: Decrypt private key - salt_len={len(salt)}, nonce_len={len(nonce)}, ciphertext_len={len(ciphertext)}, aes_key_len={len(aes_key)}, iterations={encrypted_data['iterations']}")

            # Decrypt private key
            aesgcm = AESGCM(aes_key)
            private_key_der = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Load private key from DER
            private_key = serialization.load_der_private_key(
                private_key_der,
                password=None,
                backend=default_backend()
            )
            
            security_logger.log_activity(
                action='private_key_decryption',
                status='success',
                details='Private key decrypted successfully'
            )
            return True, "Private key decrypted successfully", private_key
            
        except Exception as e:
            security_logger.log_activity(
                action='private_key_decryption',
                status='failure',
                details=f'Private key decryption failed: {type(e).__name__}: {str(e)}'
            )
            print(f"DEBUG: Private key decryption failed in key_manager.py: {type(e).__name__}: {str(e)}")
            return False, f"Private key decryption failed: {str(e)}", None
    
    def create_user_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str, Optional[Dict]]:
        """Create and store RSA key pair for user"""
        try:
            # Generate key pair
            success, message, keypair_data = self.generate_rsa_keypair()
            if not success:
                return False, message, None
            
            # Encrypt private key
            encrypt_success, encrypt_message, encrypted_data = self.encrypt_private_key(
                keypair_data['private_key'], passphrase
            )
            if not encrypt_success:
                return False, encrypt_message, None
            
            # Calculate expiration date
            created_at = datetime.now()
            expires_at = created_at + timedelta(days=self.key_expiry_days)
            
            # Store keys in database
            success, db_message = self.store_keys_in_database(
                user_id=user_id,
                public_key_pem=keypair_data['public_key_pem'],
                encrypted_private_key=encrypted_data,
                created_at=created_at,
                expires_at=expires_at
            )
            
            if not success:
                return False, db_message, None
            
            result = {
                'key_id': db_message,  # Database returns the key ID
                'public_key': keypair_data['public_key_pem'],
                'created_at': created_at.isoformat(),
                'expires_at': expires_at.isoformat(),
                'status': 'valid'
            }
            
            security_logger.log_activity(
                user_id=user_id,
                action='user_keys_created',
                status='success',
                details=f'RSA key pair created, expires: {expires_at.strftime("%Y-%m-%d")}'
            )
            
            return True, "User keys created successfully", result
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='user_keys_created',
                status='failure',
                details=f'Key creation failed: {str(e)}'
            )
            return False, f"Key creation failed: {str(e)}", None
    
    def store_keys_in_database(self, user_id: int, public_key_pem: str, 
                              encrypted_private_key: Dict, created_at: datetime, 
                              expires_at: datetime) -> Tuple[bool, Union[str, int]]:
        """Store encrypted keys in database"""
        try:
            # Convert encrypted_private_key dict to JSON string for storage
            encrypted_key_json = json.dumps(encrypted_private_key)
            print(f"DEBUG: Storing encrypted key JSON: {encrypted_key_json}")
            
            # Insert into keys table
            query = """
            INSERT INTO keys (user_id, public_key, encrypted_private_key, created_at, expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """
            
            key_id = db.execute_query(
                query, 
                (user_id, public_key_pem, encrypted_key_json, created_at, expires_at, 'valid')
            )
            
            if key_id:
                return True, key_id
            else:
                return False, "Failed to insert keys into database"
                
        except Exception as e:
            return False, f"Database storage failed: {str(e)}"
    
    def get_user_keys(self, user_id: int) -> Tuple[bool, str, Optional[Dict]]:
        """Get user's current valid keys from database"""
        try:
            query = """
            SELECT id, public_key, encrypted_private_key, created_at, expires_at, status
            FROM keys 
            WHERE user_id = ? AND status IN ('valid', 'expiring')
            ORDER BY created_at DESC
            LIMIT 1
            """
            
            result = db.execute_query(query, (user_id,), fetch=True)
            
            if not result:
                return False, "No keys found for user", None
            
            key_data = result[0]
            
            # Parse encrypted private key JSON
            print(f"DEBUG: Retrieved encrypted key data from DB: {key_data['encrypted_private_key']}")
            encrypted_private_key = json.loads(key_data['encrypted_private_key'])
            
            key_info = {
                'key_id': key_data['id'],
                'public_key': key_data['public_key'],
                'encrypted_private_key': encrypted_private_key,
                'created_at': safe_to_isoformat(key_data['created_at']),
                'expires_at': safe_to_isoformat(key_data['expires_at']),
                'status': key_data['status']
            }
            
            return True, "Keys retrieved successfully", key_info
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='get_user_keys',
                status='failure',
                details=f'Key retrieval failed: {str(e)}'
            )
            return False, f"Key retrieval failed: {str(e)}", None
    
    def check_key_status(self, user_id: int) -> Tuple[bool, str, Optional[Dict]]:
        """Check key expiration status and update if needed"""
        try:
            success, message, key_data = self.get_user_keys(user_id)
            if not success:
                return False, message, None
            
            # Parse expiration date
            expires_at = safe_to_datetime(key_data['expires_at'])
            now = datetime.now()
            
            # Calculate days until expiration
            days_until_expiry = (expires_at - now).days
            
            # Determine status
            if days_until_expiry < 0:
                new_status = 'expired'
                status_message = f"Key expired {abs(days_until_expiry)} days ago"
            elif days_until_expiry <= self.warning_days:
                new_status = 'expiring'
                status_message = f"Key expires in {days_until_expiry} days"
            else:
                new_status = 'valid'
                status_message = f"Key valid for {days_until_expiry} days"
            
            # Update status in database if changed
            if new_status != key_data['status']:
                self.update_key_status(key_data['key_id'], new_status)
                key_data['status'] = new_status
            
            result = {
                'key_id': key_data['key_id'],
                'status': new_status,
                'days_until_expiry': days_until_expiry,
                'expires_at': key_data['expires_at'],
                'created_at': key_data['created_at'],
                'status_message': status_message
            }
            
            return True, status_message, result
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='check_key_status',
                status='failure',
                details=f'Key status check failed: {str(e)}'
            )
            return False, f"Key status check failed: {str(e)}", None
    
    def update_key_status(self, key_id: int, status: str) -> bool:
        """Update key status in database"""
        try:
            query = "UPDATE keys SET status = ? WHERE id = ?"
            rows_affected = db.execute_query(query, (status, key_id))
            return rows_affected > 0
        except Exception as e:
            security_logger.log_activity(
                action='update_key_status',
                status='failure',
                details=f'Key status update failed: {str(e)}'
            )
            return False
    
    def renew_user_keys(self, user_id: int, passphrase: str) -> Tuple[bool, str, Optional[Dict]]:
        """Generate new keys for user and mark old ones as expired"""
        try:
            # Mark existing keys as expired
            query = "UPDATE keys SET status = 'expired' WHERE user_id = ? AND status IN ('valid', 'expiring')"
            db.execute_query(query, (user_id,))
            
            # Create new keys
            success, message, key_data = self.create_user_keys(user_id, passphrase)
            
            if success:
                security_logger.log_activity(
                    user_id=user_id,
                    action='key_renewal',
                    status='success',
                    details='RSA keys renewed successfully'
                )
            
            return success, message, key_data
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='key_renewal',
                status='failure',
                details=f'Key renewal failed: {str(e)}'
            )
            return False, f"Key renewal failed: {str(e)}", None
    
    def validate_keypair(self, public_key_pem: str, private_key) -> Tuple[bool, str]:
        """Validate that public and private keys are a matching pair"""
        try:
            # Load public key from PEM
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Get public key from private key
            derived_public_key = private_key.public_key()
            
            # Compare public key components
            pub_numbers = public_key.public_numbers()
            derived_numbers = derived_public_key.public_numbers()
            
            if (pub_numbers.n == derived_numbers.n and 
                pub_numbers.e == derived_numbers.e):
                return True, "Key pair is valid"
            else:
                return False, "Public and private keys do not match"
                
        except Exception as e:
            return False, f"Key validation failed: {str(e)}"
    
    def get_all_user_keys(self, user_id: int) -> Tuple[bool, str, Optional[list]]:
        """Get all keys for a user (including expired ones)"""
        try:
            query = """
            SELECT id, created_at, expires_at, status
            FROM keys 
            WHERE user_id = ?
            ORDER BY created_at DESC
            """
            
            results = db.execute_query(query, (user_id,), fetch=True)
            
            if not results:
                return False, "No keys found for user", None
            
            keys_list = []
            for key_data in results:
                key_info = {
                    'key_id': key_data['id'],
                    'created_at': safe_to_isoformat(key_data['created_at']),
                    'expires_at': safe_to_isoformat(key_data['expires_at']),
                    'status': key_data['status']
                }
                keys_list.append(key_info)
            
            return True, f"Retrieved {len(keys_list)} keys", keys_list
            
        except Exception as e:
            return False, f"Failed to retrieve keys: {str(e)}", None

    def get_private_key(self, user_email: str, passphrase: str):
        """Retrieve and decrypt the user's current RSA private key.

        Args:
            user_email (str): The email address of the user who owns the key.
            passphrase (str): The user's passphrase to decrypt the private key.

        Returns:
            object | None: The deserialized private key object on success, or None on failure.
        """
        try:
            # Look up the user and their latest valid/expiring key
            user_record = db.get_user_by_email(user_email.lower().strip())
            if not user_record:
                security_logger.log_activity(action="get_private_key", status="failure", details=f"User not found: {user_email}")
                return None

            user_id = user_record['id']
            
            # Get the most recent key directly from the database
            query = """
            SELECT id, public_key, encrypted_private_key, created_at, expires_at, status
            FROM keys 
            WHERE user_id = ? AND status IN ('valid', 'expiring')
            ORDER BY created_at DESC
            LIMIT 1
            """
            key_records = db.execute_query(query, (user_id,), fetch=True)
            if not key_records or len(key_records) == 0:
                security_logger.log_activity(user_id=user_id, action="get_private_key", status="failure", details="No valid key record found")
                return None
                
            key_record = key_records[0]
            print(f"DEBUG: Retrieved encrypted key data from DB: {key_record['encrypted_private_key']}")

            # Parse the encrypted_private_key JSON
            try:
                encrypted_data = json.loads(key_record['encrypted_private_key'])
            except Exception as e:
                security_logger.log_activity(user_id=user_id, action="get_private_key", status="failure", details=f"Invalid encrypted key JSON: {str(e)}")
                return None

            # Decrypt the private key
            decrypt_success, decrypt_message, private_key_obj = self.decrypt_private_key(encrypted_data, passphrase)
            if not decrypt_success or not private_key_obj:
                security_logger.log_activity(user_id=user_id, action="get_private_key", status="failure", details=f"Private key decryption failed: {decrypt_message}")
                return None

            security_logger.log_activity(user_id=user_id, action="get_private_key", status="success", details="Private key retrieved and decrypted")
            return private_key_obj

        except Exception as e:
            security_logger.log_activity(action="get_private_key", status="error", details=f"Unexpected error: {type(e).__name__}: {str(e)}")
            return None

# Create global instance
key_manager = KeyManager()
