from PyQt5.QtCore import QObject, pyqtSignal
import time
from pathlib import Path

class EncryptionWorker(QObject):
    """Worker thread for file encryption operations"""
    
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(bool, str, dict)
    error = pyqtSignal(str)
    
    def __init__(self, file_path, recipient_email, user_id, output_format):
        super().__init__()
        self.file_path = file_path
        self.recipient_email = recipient_email
        self.user_id = user_id
        self.output_format = output_format
        
    def encrypt(self):
        """Perform file encryption with progress updates"""
        try:
            from modules.file_crypto import FileCrypto
            
            self.log_message.emit("Starting file encryption...")
            self.progress.emit(10)
            
            # Initialize crypto module
            crypto = FileCrypto()
            file_path = Path(self.file_path)
            
            # Check if it's a large file
            is_large = crypto.is_large_file(self.file_path)
            if is_large:
                self.log_message.emit(f"Large file detected (>{crypto.large_file_threshold / (1024*1024):.0f}MB), using block encryption...")
            else:
                self.log_message.emit("Standard file encryption mode")
                
            self.progress.emit(20)
            
            # Perform encryption
            self.log_message.emit(f"Encrypting for recipient: {self.recipient_email}")
            success, message, result_info = crypto.encrypt_file(
                file_path=self.file_path,
                recipient_email=self.recipient_email,
                sender_user_id=self.user_id,
                output_format=self.output_format
            )
            
            if success:
                self.progress.emit(80)
                self.log_message.emit("Encryption completed successfully")
                
                # Prepare result information
                output_file = result_info.get('output_file', 'Unknown')
                file_size = result_info.get('file_size', 0)
                encrypted_size = result_info.get('encrypted_size', 0)
                
                self.log_message.emit(f"Output file: {output_file}")
                if file_size > 0 and encrypted_size > 0:
                    ratio = encrypted_size / file_size
                    self.log_message.emit(f"Size: {file_size} bytes → {encrypted_size} bytes (ratio: {ratio:.2f}x)")
                
                if self.output_format == 'separate' and result_info.get('key_file'):
                    self.log_message.emit(f"Key file: {result_info['key_file']}")
                
                self.progress.emit(100)
                time.sleep(0.5)  # Brief pause to show completion
                
                self.finished.emit(True, "Encryption completed successfully", result_info)
            else:
                self.log_message.emit(f"Encryption failed: {message}")
                self.error.emit(message)
                
        except Exception as e:
            error_msg = f"Encryption error: {str(e)}"
            self.log_message.emit(error_msg)
            self.error.emit(error_msg) 
