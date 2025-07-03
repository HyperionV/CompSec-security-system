#!/usr/bin/env python3
"""
File Encryption Module using Hybrid RSA+AES Cryptography
Enhanced with Large File Block Processing (Phase 12)
"""

import os
import json
import secrets
import struct
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .database import db
from .logger import security_logger

class FileCrypto:
    def __init__(self):
        self.aes_key_length = 32  # 256 bits
        self.nonce_length = 12   # 96 bits for GCM
        self.large_file_threshold = 5 * 1024 * 1024  # 5MB
        self.block_size = 1 * 1024 * 1024  # 1MB blocks
        
    def generate_session_key(self) -> bytes:
        """Generate a secure random AES session key"""
        return secrets.token_bytes(self.aes_key_length)
    
    def generate_nonce(self) -> bytes:
        """Generate a secure random nonce for AES-GCM"""
        return secrets.token_bytes(self.nonce_length)
    
    def is_large_file(self, file_path: str) -> bool:
        """Check if file is larger than 5MB threshold"""
        return os.path.getsize(file_path) > self.large_file_threshold
    
    def encrypt_file_blocks(self, file_path: str, session_key: bytes) -> Tuple[bytes, Dict]:
        """Encrypt large file using 1MB block processing with AES-GCM"""
        file_size = os.path.getsize(file_path)
        total_blocks = (file_size + self.block_size - 1) // self.block_size
        
        security_logger.log_activity(
            user_id=0,
            action='large_file_encryption_start',
            status='info',
            details=f'Starting block encryption: {total_blocks} blocks, {file_size} bytes'
        )
        
        encrypted_blocks = []
        
        with open(file_path, 'rb') as f:
            for block_num in range(total_blocks):
                # Read block data
                block_data = f.read(self.block_size)
                if not block_data:
                    break
                
                # Generate unique nonce for this block (CRITICAL for security)
                block_nonce = self.generate_nonce()
                
                # Encrypt block with AES-GCM
                aesgcm = AESGCM(session_key)
                block_ciphertext = aesgcm.encrypt(block_nonce, block_data, None)
                
                # Create block metadata
                block_info = {
                    'block_number': block_num,
                    'nonce': block_nonce.hex(),
                    'ciphertext_length': len(block_ciphertext),
                    'ciphertext': block_ciphertext.hex()
                }
                encrypted_blocks.append(block_info)
                
                # Log progress
                security_logger.log_activity(
                    user_id=0,
                    action='block_encrypted',
                    status='success',
                    details=f'Block {block_num + 1}/{total_blocks} encrypted ({len(block_data)} bytes → {len(block_ciphertext)} bytes)'
                )
        
        # Create block file header
        block_header = {
            'format_type': 'large_file_blocks',
            'original_size': file_size,
            'total_blocks': total_blocks,
            'block_size': self.block_size,
            'encryption_algorithm': 'AES-256-GCM',
            'blocks': encrypted_blocks
        }
        
        # Serialize to bytes for storage
        header_json = json.dumps(block_header).encode('utf-8')
        
        # Calculate size comparison
        encrypted_size = len(header_json)
        for block in encrypted_blocks:
            encrypted_size += block['ciphertext_length']
        
        security_logger.log_activity(
            user_id=0,
            action='large_file_encryption_complete',
            status='success',
            details=f'Large file encrypted: {file_size} bytes → {encrypted_size} bytes (ratio: {encrypted_size/file_size:.2f}x)'
        )
        
        return header_json, block_header
    
    def decrypt_file_blocks(self, block_data: bytes, session_key: bytes) -> Tuple[bytes, Dict]:
        """Decrypt large file from block format"""
        # Parse block header
        try:
            block_header = json.loads(block_data.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid block header format: {e}")
        
        # Validate block format
        if block_header.get('format_type') != 'large_file_blocks':
            raise ValueError("Not a valid large file block format")
        
        original_size = block_header['original_size']
        total_blocks = block_header['total_blocks']
        blocks = block_header['blocks']
        
        security_logger.log_activity(
            user_id=0,
            action='large_file_decryption_start',
            status='info',
            details=f'Starting block decryption: {total_blocks} blocks, {original_size} bytes expected'
        )
        
        # Decrypt blocks in order
        decrypted_data = b''
        
        for i, block_info in enumerate(blocks):
            block_num = block_info['block_number']
            block_nonce = bytes.fromhex(block_info['nonce'])
            block_ciphertext = bytes.fromhex(block_info['ciphertext'])
            
            # Verify block order
            if block_num != i:
                raise ValueError(f"Block order error: expected block {i}, got block {block_num}")
            
            try:
                # Decrypt block with AES-GCM
                aesgcm = AESGCM(session_key)
                block_plaintext = aesgcm.decrypt(block_nonce, block_ciphertext, None)
                decrypted_data += block_plaintext
                
                # Log progress
                security_logger.log_activity(
                    user_id=0,
                    action='block_decrypted',
                    status='success',
                    details=f'Block {block_num + 1}/{total_blocks} decrypted ({len(block_ciphertext)} bytes → {len(block_plaintext)} bytes)'
                )
                
            except Exception as e:
                security_logger.log_activity(
                    user_id=0,
                    action='block_decrypted',
                    status='failure',
                    details=f'Block {block_num} integrity check failed: {e}'
                )
                raise ValueError(f"Block {block_num} integrity verification failed: {e}")
        
        # Verify final size
        if len(decrypted_data) != original_size:
            raise ValueError(f"Size mismatch: expected {original_size}, got {len(decrypted_data)}")
        
        security_logger.log_activity(
            user_id=0,
            action='large_file_decryption_complete',
            status='success',
            details=f'Large file decrypted: {len(decrypted_data)} bytes restored'
        )
        
        return decrypted_data, block_header
    
    def encrypt_file(self, file_path: str, recipient_email: str, sender_user_id: int, 
                    output_format: str = 'combined') -> Tuple[bool, str, Optional[Dict]]:
        """Encrypt a file using hybrid RSA+AES encryption with large file support"""
        try:
            # Validate input file
            if not os.path.exists(file_path):
                return False, "File not found", None
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return False, "Cannot encrypt empty file", None
            
            # Get recipient's public key
            public_key_data = db.search_public_key_by_email(sender_user_id, recipient_email)
            if not public_key_data:
                return False, f"No public key found for {recipient_email}", None
            
            # Load recipient's public key
            recipient_public_key = serialization.load_pem_public_key(
                public_key_data['public_key'].encode('utf-8'),
                backend=default_backend()
            )
            
            # Get sender info
            sender_info = db.get_user_by_id(sender_user_id)
            if not sender_info:
                return False, "Sender not found", None
            
            # Generate session key
            session_key = self.generate_session_key()
            
            # Check if file is large and needs block processing
            is_large = self.is_large_file(file_path)
            
            # Create metadata
            metadata = {
                'sender_email': sender_info['email'],
                'recipient_email': recipient_email,
                'original_filename': os.path.basename(file_path),
                'file_size': file_size,
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM',
                'format_version': '1.0',
                'is_large_file': is_large
            }
            
            if is_large:
                # Large file processing with blocks
                security_logger.log_activity(
                    user_id=sender_user_id,
                    action='file_encryption_large_detected',
                    status='info',
                    details=f'Large file detected ({file_size} bytes), using block processing'
                )
                
                # Encrypt using block processing
                block_data, block_header = self.encrypt_file_blocks(file_path, session_key)
                
                # Use block data as the "ciphertext"
                nonce = b''  # Not used for block format
                ciphertext = block_data
                
            else:
                # Regular file processing
                nonce = self.generate_nonce()
                
                # Read and encrypt file content
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                # Encrypt file with AES-GCM
                aesgcm = AESGCM(session_key)
                metadata_bytes = json.dumps(metadata).encode('utf-8')
                
                # Encrypt with metadata as associated data for integrity
                ciphertext = aesgcm.encrypt(nonce, file_content, metadata_bytes)
            
            # Encrypt session key with recipient's RSA public key (same for both file types)
            encrypted_session_key = recipient_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Create output filenames
            base_name = Path(file_path).stem
            output_dir = Path(file_path).parent / "encrypted"
            output_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if output_format == 'combined':
                # Combined format: everything in one .enc file
                enc_file = output_dir / f"{base_name}_{timestamp}.enc"
                
                if is_large:
                    # Store as binary data for large files
                    combined_data = {
                        'metadata': metadata,
                        'nonce': '',  # Empty for block format
                        'encrypted_session_key': encrypted_session_key.hex(),
                        'ciphertext': ciphertext.decode('utf-8')  # Block data as JSON string
                    }
                else:
                    combined_data = {
                        'metadata': metadata,
                        'nonce': nonce.hex(),
                        'encrypted_session_key': encrypted_session_key.hex(),
                        'ciphertext': ciphertext.hex()
                    }
                
                with open(enc_file, 'w') as f:
                    json.dump(combined_data, f, indent=2)
                
                result = {
                    'encrypted_file': str(enc_file),
                    'format': 'combined',
                    'metadata': metadata
                }
                
            else:
                # Separate format: .enc file + .key file
                enc_file = output_dir / f"{base_name}_{timestamp}.enc"
                key_file = output_dir / f"{base_name}_{timestamp}.key"
                
                # Save encrypted file content
                if is_large:
                    enc_data = {
                        'metadata': metadata,
                        'nonce': '',  # Empty for block format
                        'ciphertext': ciphertext.decode('utf-8')  # Block data as JSON string
                    }
                else:
                    enc_data = {
                        'metadata': metadata,
                        'nonce': nonce.hex(),
                        'ciphertext': ciphertext.hex()
                    }
                
                with open(enc_file, 'w') as f:
                    json.dump(enc_data, f, indent=2)
                
                # Save encrypted session key
                key_data = {
                    'encrypted_session_key': encrypted_session_key.hex(),
                    'recipient_email': recipient_email,
                    'sender_email': sender_info['email'],
                    'timestamp': metadata['timestamp']
                }
                
                with open(key_file, 'w') as f:
                    json.dump(key_data, f, indent=2)
                
                result = {
                    'encrypted_file': str(enc_file),
                    'key_file': str(key_file),
                    'format': 'separate',
                    'metadata': metadata
                }
            
            # Log successful encryption
            file_type = "large file" if is_large else "regular file"
            security_logger.log_activity(
                user_id=sender_user_id,
                action='file_encrypted',
                status='success',
                details=f'{file_type.title()} {os.path.basename(file_path)} encrypted for {recipient_email}'
            )
            
            return True, f"File encrypted successfully ({file_type})", result
            
        except Exception as e:
            security_logger.log_activity(
                user_id=sender_user_id,
                action='file_encrypted',
                status='failure',
                details=f'Encryption failed: {str(e)}'
            )
            return False, f"Encryption failed: {str(e)}", None
    
    def decrypt_file(self, encrypted_file_path: str, user_id: int, passphrase: str,
                    key_file_path: Optional[str] = None) -> Tuple[bool, str, Optional[Dict]]:
        """Decrypt a file using hybrid RSA+AES decryption with large file support"""
        try:
            # Load encrypted file
            if not os.path.exists(encrypted_file_path):
                return False, "Encrypted file not found", None
            
            with open(encrypted_file_path, 'r') as f:
                enc_data = json.load(f)
            
            # Determine format and load data
            if 'encrypted_session_key' in enc_data:
                # Combined format
                metadata = enc_data['metadata']
                nonce_hex = enc_data['nonce']
                encrypted_session_key = bytes.fromhex(enc_data['encrypted_session_key'])
                ciphertext_data = enc_data['ciphertext']
            else:
                # Separate format - need key file
                if not key_file_path or not os.path.exists(key_file_path):
                    return False, "Key file required for separate format", None
                
                with open(key_file_path, 'r') as f:
                    key_data = json.load(f)
                
                metadata = enc_data['metadata']
                nonce_hex = enc_data['nonce']
                encrypted_session_key = bytes.fromhex(key_data['encrypted_session_key'])
                ciphertext_data = enc_data['ciphertext']
            
            # Check if this is a large file
            is_large_file = metadata.get('is_large_file', False)
            
            # Get user's private key
            from .key_manager import key_manager
            
            success, message, key_data = key_manager.get_user_keys(user_id)
            if not success:
                return False, f"Failed to get private key: {message}", None
            
            # Decrypt private key
            decrypt_success, decrypt_message, private_key = key_manager.decrypt_private_key(
                key_data['encrypted_private_key'], passphrase
            )
            if not decrypt_success:
                return False, f"Failed to decrypt private key: {decrypt_message}", None
            
            # Decrypt session key
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file content based on type
            if is_large_file:
                # Large file block decryption
                security_logger.log_activity(
                    user_id=user_id,
                    action='file_decryption_large_detected',
                    status='info',
                    details='Large file format detected, using block processing'
                )
                
                # Parse block data
                block_data = ciphertext_data.encode('utf-8')
                plaintext, block_info = self.decrypt_file_blocks(block_data, session_key)
                
            else:
                # Regular file decryption
                nonce = bytes.fromhex(nonce_hex)
                ciphertext = bytes.fromhex(ciphertext_data)
                
                # Decrypt file content
                aesgcm = AESGCM(session_key)
                metadata_bytes = json.dumps(metadata).encode('utf-8')
                
                # Decrypt with metadata verification
                plaintext = aesgcm.decrypt(nonce, ciphertext, metadata_bytes)
            
            # Create output filename
            output_dir = Path(encrypted_file_path).parent / "decrypted"
            output_dir.mkdir(exist_ok=True)
            
            original_filename = metadata['original_filename']
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = output_dir / f"decrypted_{timestamp}_{original_filename}"
            
            # Write decrypted content
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            result = {
                'decrypted_file': str(output_file),
                'metadata': metadata,
                'file_size': len(plaintext)
            }
            
            # Log successful decryption
            file_type = "large file" if is_large_file else "regular file"
            security_logger.log_activity(
                user_id=user_id,
                action='file_decrypted',
                status='success',
                details=f'{file_type.title()} {metadata["original_filename"]} decrypted from {metadata["sender_email"]}'
            )
            
            return True, f"File decrypted successfully ({file_type})", result
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='file_decrypted',
                status='failure',
                details=f'Decryption failed: {str(e)}'
            )
            return False, f"Decryption failed: {str(e)}", None

# Create global instance
file_crypto = FileCrypto()
