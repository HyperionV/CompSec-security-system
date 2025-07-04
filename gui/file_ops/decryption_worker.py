from PyQt5.QtCore import QObject, pyqtSignal
import time
from pathlib import Path

class DecryptionWorker(QObject):
    """Worker thread for file decryption operations"""
    
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(bool, str, dict)
    error = pyqtSignal(str)
    
    def __init__(self, encrypted_file_path, key_file_path, user_id, passphrase):
        super().__init__()
        self.encrypted_file_path = encrypted_file_path
        self.key_file_path = key_file_path
        self.user_id = user_id
        self.passphrase = passphrase
        
    def decrypt(self):
        """Perform file decryption with progress updates"""
        try:
            from modules.file_crypto import FileCrypto
            
            self.log_message.emit("Starting file decryption...")
            self.progress.emit(10)
            
            # Initialize crypto module
            crypto = FileCrypto()
            
            # Auto-detect file format
            if self.key_file_path:
                self.log_message.emit("Using separate key file format")
                format_info = "separate format"
            else:
                self.log_message.emit("Attempting combined file format")
                format_info = "combined format"
                
            self.progress.emit(20)
            
            # Perform decryption
            self.log_message.emit(f"Decrypting file ({format_info})...")
            success, message, result_info = crypto.decrypt_file(
                encrypted_file_path=self.encrypted_file_path,
                user_id=self.user_id,
                passphrase=self.passphrase,
                key_file_path=self.key_file_path
            )
            
            if success:
                self.progress.emit(80)
                self.log_message.emit("Decryption completed successfully")
                
                # Prepare result information
                output_file = result_info.get('output_file', 'Unknown')
                sender = result_info.get('sender', 'Unknown')
                original_filename = result_info.get('original_filename', 'Unknown')
                file_size = result_info.get('file_size', 0)
                
                self.log_message.emit(f"Output file: {output_file}")
                self.log_message.emit(f"Sender: {sender}")
                if original_filename != 'Unknown':
                    self.log_message.emit(f"Original filename: {original_filename}")
                if file_size > 0:
                    size_str = f"{file_size} bytes"
                    if file_size > 1024 * 1024:
                        size_str = f"{file_size / (1024 * 1024):.1f} MB"
                    elif file_size > 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    self.log_message.emit(f"File size: {size_str}")
                
                self.progress.emit(100)
                time.sleep(0.5)  # Brief pause to show completion
                
                self.finished.emit(True, "Decryption completed successfully", result_info)
            else:
                self.log_message.emit(f"Decryption failed: {message}")
                self.error.emit(message)
                
        except Exception as e:
            error_msg = f"Decryption error: {str(e)}"
            self.log_message.emit(error_msg)
            self.error.emit(error_msg) 
