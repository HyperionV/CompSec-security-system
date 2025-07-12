import os
import json
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class SignatureVerification:
    def __init__(self, user_email, database, logger):
        self.user_email = user_email
        self.database = database
        self.logger = logger
    
    def verify_signature(self, file_path, signature_path=None):
        try:
            if not signature_path:
                signature_path = file_path + ".sig"
            
            if not os.path.isfile(file_path):
                return False, "Original file not found"
            
            if not os.path.isfile(signature_path):
                return False, "Signature file not found"
            
            print(f"DEBUG: Verifying file: {file_path}")
            print(f"DEBUG: With signature: {signature_path}")
            
            metadata, signature_bytes = self._parse_signature_file(signature_path)
            if not metadata or not signature_bytes:
                return False, "Invalid signature file format"
            
            # Read the file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Calculate hash of the file data for metadata verification only
            hash_obj = hashlib.sha256(file_data)
            file_hash_hex = hash_obj.hexdigest()
            
            print(f"DEBUG: File to verify: {file_path}")
            print(f"DEBUG: Calculated hash (hex): {file_hash_hex}")
            print(f"DEBUG: Expected hash from signature: {metadata.get('file_hash', 'Not found')}")
            print(f"DEBUG: File data length: {len(file_data)} bytes")
            print(f"DEBUG: Signature length: {len(signature_bytes)} bytes")
            
            # Check if the calculated hash matches the one in the signature metadata
            if file_hash_hex != metadata.get('file_hash'):
                print("DEBUG: Hash mismatch! File may have been modified.")
                self.logger.log_action(
                    self.user_email, 
                    "SIGNATURE_VERIFICATION", 
                    "FAILED", 
                    f"Hash mismatch for {os.path.basename(file_path)}"
                )
                return False, "Signature verification failed: File hash does not match signature."
            
            # Try direct verification with the signer's key if they are the current user
            if metadata.get('signer_email') == self.user_email:
                print("DEBUG: Signer is current user, trying direct verification with user's key")
                direct_result = self._try_direct_verification(file_data, signature_bytes)
                if direct_result:
                    success_msg = f"Signature verified! Signed by: {metadata['signer_email']} on {metadata['timestamp']}"
                    self.logger.log_action(
                        self.user_email, 
                        "SIGNATURE_VERIFICATION", 
                        "SUCCESS", 
                        f"Verified signature for {os.path.basename(file_path)} by {metadata['signer_email']}"
                    )
                    return True, success_msg
            
            # Try with all available public keys
            public_keys = self._get_all_public_keys()
            if not public_keys:
                return False, "No public keys available for verification"
            
            for key_info in public_keys:
                public_key = key_info['key']
                key_owner = key_info['owner']
                
                try:
                    # Verify using the file data directly
                    public_key.verify(
                        signature_bytes,
                        file_data,  # Verify against file data, not hash
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print(f"DEBUG: Verification SUCCESSFUL with key from {key_owner}")
                    success_msg = f"Signature verified! Signed by: {metadata['signer_email']} on {metadata['timestamp']}"
                    self.logger.log_action(
                        self.user_email, 
                        "SIGNATURE_VERIFICATION", 
                        "SUCCESS", 
                        f"Verified signature for {os.path.basename(file_path)} by {metadata['signer_email']}"
                    )
                    return True, success_msg
                except InvalidSignature:
                    print(f"DEBUG: InvalidSignature with key from {key_owner}")
                    continue
                except Exception as e:
                    print(f"DEBUG: Exception during verification with key from {key_owner}: {type(e).__name__}: {str(e)}")
                    continue
            
            self.logger.log_action(
                self.user_email, 
                "SIGNATURE_VERIFICATION", 
                "FAILED", 
                f"Failed to verify signature for {os.path.basename(file_path)}"
            )
            return False, "Signature verification failed. Invalid signature or no matching public key found."
            
        except Exception as e:
            self.logger.log_action(
                self.user_email, 
                "SIGNATURE_VERIFICATION", 
                "ERROR", 
                f"Error verifying signature: {str(e)}"
            )
            return False, f"Verification error: {str(e)}"
    
    def verify_directly(self, file_path, signature_path, public_key_pem):
        """Directly verify a file signature using a specific public key."""
        try:
            if not os.path.isfile(file_path):
                return False, "Original file not found"
            
            if not os.path.isfile(signature_path):
                return False, "Signature file not found"
            
            # Read the file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Parse the signature file
            metadata, signature_bytes = self._parse_signature_file(signature_path)
            if not metadata or not signature_bytes:
                return False, "Invalid signature file format"
            
            # Load the public key
            try:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                print(f"DEBUG: Loaded public key for direct verification, length: {len(public_key_pem)}")
            except Exception as e:
                print(f"DEBUG: Error loading public key: {type(e).__name__}: {str(e)}")
                return False, f"Error loading public key: {str(e)}"
            
            # Verify the signature
            try:
                public_key.verify(
                    signature_bytes,
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("DEBUG: Direct verification successful!")
                return True, "Signature verified successfully"
            except InvalidSignature:
                print("DEBUG: Direct verification failed: Invalid signature")
                return False, "Invalid signature"
            except Exception as e:
                print(f"DEBUG: Error during direct verification: {type(e).__name__}: {str(e)}")
                return False, f"Verification error: {str(e)}"
                
        except Exception as e:
            print(f"DEBUG: Exception in verify_directly: {type(e).__name__}: {str(e)}")
            return False, f"Verification error: {str(e)}"
    
    def _try_direct_verification(self, file_data, signature_bytes):
        """Try to verify using the user's own key directly from the database."""
        try:
            user_id = self.database.get_user_id(self.user_email)
            if not user_id:
                print("DEBUG: User ID not found for direct verification")
                return False
            
            user_key = self.database.get_user_public_key(user_id)
            if not user_key:
                print("DEBUG: User public key not found for direct verification")
                return False
            
            print(f"DEBUG: Got user public key for direct verification, length: {len(user_key)}")
            print(f"DEBUG: Key starts with: {user_key[:50]}...")
            
            public_key = serialization.load_pem_public_key(user_key.encode())
            
            # Try verification with different approaches
            try:
                # Approach 1: Standard verification
                public_key.verify(
                    signature_bytes,
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("DEBUG: Direct verification successful with approach 1")
                return True
            except Exception as e1:
                print(f"DEBUG: Direct verification approach 1 failed: {type(e1).__name__}: {str(e1)}")
            
            return False
        except Exception as e:
            print(f"DEBUG: Error in direct verification: {type(e).__name__}: {str(e)}")
            return False
    
    def _parse_signature_file(self, signature_path):
        try:
            print(f"DEBUG: Parsing signature file: {signature_path}")
            with open(signature_path, 'rb') as f:
                content = f.read()
            
            print(f"DEBUG: Signature file size: {len(content)} bytes")
            
            # Look for the delimiter with newline to ensure exact matching
            delimiter = b"---SIGNATURE---\n"
            if delimiter not in content:
                # Try without newline as fallback
                delimiter = b"---SIGNATURE---"
                if delimiter not in content:
                    print("DEBUG: Signature delimiter not found in file")
                    return None, None
            
            parts = content.split(delimiter, 1)
            if len(parts) != 2:
                print("DEBUG: Incorrect number of parts after splitting")
                return None, None
            
            metadata_json = parts[0].decode('utf-8')
            signature_bytes = parts[1].strip()  # Strip any trailing whitespace
            
            print(f"DEBUG: Metadata length: {len(metadata_json)}, Signature length: {len(signature_bytes)}")
            
            try:
                metadata = json.loads(metadata_json)
                print(f"DEBUG: Parsed metadata: {metadata}")
                return metadata, signature_bytes
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON decode error: {e}")
                return None, None
                
        except (IOError, UnicodeDecodeError) as e:
            print(f"DEBUG: Error reading signature file: {type(e).__name__}: {str(e)}")
            return None, None
    
    def _calculate_file_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
        result = hash_sha256.digest()
        print(f"DEBUG: Calculated file hash (hex): {hash_sha256.hexdigest()}")
        print(f"DEBUG: Calculated file hash (bytes): {len(result)} bytes")
        return result
    
    def _get_all_public_keys(self):
        public_keys = []
        
        # Get user's own public key
        user_id = self.database.get_user_id(self.user_email)
        if user_id:
            print(f"DEBUG: Getting public key for user ID: {user_id}, email: {self.user_email}")
            user_key = self.database.get_user_public_key(user_id)
            if user_key:
                try:
                    print(f"DEBUG: Found user's own public key, length: {len(user_key)}")
                    print(f"DEBUG: Key starts with: {user_key[:50]}...")
                    public_key = serialization.load_pem_public_key(user_key.encode())
                    public_keys.append({
                        'key': public_key,
                        'owner': self.user_email
                    })
                except Exception as e:
                    print(f"DEBUG: Error loading user's public key: {type(e).__name__}: {str(e)}")
            else:
                print(f"DEBUG: No public key found for user ID: {user_id}")
        else:
            print(f"DEBUG: User ID not found for email: {self.user_email}")
        
        # Get all imported public keys
        imported_keys = self.database.get_all_public_keys()
        print(f"DEBUG: Found {len(imported_keys)} imported public keys")
        
        for key_record in imported_keys:
            try:
                email = key_record.get('email')
                key_data = key_record.get('public_key')
                print(f"DEBUG: Processing imported key for: {email}, length: {len(key_data)}")
                print(f"DEBUG: Key starts with: {key_data[:50]}...")
                
                public_key = serialization.load_pem_public_key(key_data.encode())
                public_keys.append({
                    'key': public_key,
                    'owner': email
                })
            except Exception as e:
                print(f"DEBUG: Error loading imported public key: {type(e).__name__}: {str(e)}")
                continue
        
        print(f"DEBUG: Total public keys loaded: {len(public_keys)}")
        return public_keys 