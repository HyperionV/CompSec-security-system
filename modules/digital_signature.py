import os
import json
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .logger import security_logger

class DigitalSignature:
    def __init__(self, user_email, key_manager, database, logger):
        self.user_email = user_email
        self.key_manager = key_manager
        self.database = database
        self.logger = logger
        self.signatures_dir = "data/signatures"
        self._ensure_directories()
    
    def _ensure_directories(self):
        os.makedirs(self.signatures_dir, exist_ok=True)
    
    def sign_file(self, file_path, passphrase):
        try:
            if not os.path.isfile(file_path):
                return False, "File not found"

            # Retrieve and decrypt private key
            private_key = self.key_manager.get_private_key(self.user_email, passphrase)
            if not private_key:
                return False, "Failed to decrypt private key"

            # Read the file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Calculate file hash for metadata
            hash_obj = hashlib.sha256(file_data)
            file_hash_hex = hash_obj.hexdigest()

            # Attempt to sign the file data directly
            signature = private_key.sign(
                file_data,  # Sign the file data directly
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            filename = os.path.basename(file_path)
            metadata = self._create_signature_metadata(filename, file_hash_hex)
            sig_file_path = self._save_signature_file(filename, metadata, signature)

            security_logger.log_activity(
                action='file_signed',
                status='success',
                details=f'File: {filename}, Hash: {file_hash_hex[:16]}...',
                email=self.user_email
            )

            return True, sig_file_path

        except Exception as e:
            security_logger.log_activity(
                action='file_sign_error',
                status='failure',
                details=str(e),
                email=self.user_email
            )
            return False, f"Signing failed: {str(e)}"
    
    def _calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _create_signature_metadata(self, filename, file_hash):
        return {
            "signer_email": self.user_email,
            "original_filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_hash": file_hash,
            "algorithm": "SHA-256",
            "padding": "PSS",
            "mgf": "MGF1(SHA256)",
            "salt_length": "max",
            "format_version": "1.0"
        }
    
    def _save_signature_file(self, filename, metadata, signature):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(filename)[0]
        sig_filename = f"{base_name}_{timestamp}.sig"
        sig_file_path = os.path.join(self.signatures_dir, sig_filename)
        with open(sig_file_path, 'wb') as f:
            metadata_json = json.dumps(metadata, indent=2)
            f.write(metadata_json.encode('utf-8'))
            f.write(b'\n---SIGNATURE---\n')
            f.write(signature)
        
        return sig_file_path 