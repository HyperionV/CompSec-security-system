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
            
            metadata, signature_bytes = self._parse_signature_file(signature_path)
            if not metadata or not signature_bytes:
                return False, "Invalid signature file format"
            
            file_hash = self._calculate_file_hash(file_path)
            
            public_keys = self._get_all_public_keys()
            if not public_keys:
                return False, "No public keys available for verification"
            
            for key_info in public_keys:
                public_key = key_info['key']
                key_owner = key_info['owner']
                
                if self._verify_with_key(public_key, signature_bytes, file_hash):
                    success_msg = f"Signature verified! Signed by: {metadata['signer_email']} on {metadata['timestamp']}"
                    self.logger.log_action(
                        self.user_email, 
                        "SIGNATURE_VERIFICATION", 
                        "SUCCESS", 
                        f"Verified signature for {os.path.basename(file_path)} by {metadata['signer_email']}"
                    )
                    return True, success_msg, metadata
            
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
    
    def _parse_signature_file(self, signature_path):
        try:
            with open(signature_path, 'rb') as f:
                content = f.read()
            
            if b"---SIGNATURE---" not in content:
                return None, None
            
            parts = content.split(b"---SIGNATURE---", 1)
            if len(parts) != 2:
                return None, None
            
            metadata_json = parts[0].decode('utf-8')
            signature_bytes = parts[1]
            
            metadata = json.loads(metadata_json)
            return metadata, signature_bytes
            
        except (IOError, json.JSONDecodeError, UnicodeDecodeError):
            return None, None
    
    def _calculate_file_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
        return hash_sha256.digest()
    
    def _get_all_public_keys(self):
        public_keys = []
        
        # Get user's own public key
        user_id = self.database.get_user_id(self.user_email)
        if user_id:
            user_key = self.database.get_user_public_key(user_id)
            if user_key:
                try:
                    public_key = serialization.load_pem_public_key(user_key.encode())
                    public_keys.append({
                        'key': public_key,
                        'owner': self.user_email
                    })
                except Exception:
                    pass
        
        # Get all imported public keys
        imported_keys = self.database.get_all_public_keys()
        for key_record in imported_keys:
            try:
                public_key = serialization.load_pem_public_key(key_record['public_key'].encode())
                public_keys.append({
                    'key': public_key,
                    'owner': key_record['email']
                })
            except Exception:
                continue
        
        return public_keys
    
    def _verify_with_key(self, public_key, signature_bytes, file_hash):
        try:
            public_key.verify(
                signature_bytes,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False 