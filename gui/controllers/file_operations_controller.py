from PyQt5.QtCore import QObject, pyqtSignal

from .base_controller import BaseController
from ..file_ops.file_operations_window import FileOperationsWindow

class FileOperationsController(BaseController):
    """Controller for managing file encryption and decryption operations"""
    
    def __init__(self, session_manager, parent=None):
        super().__init__(session_manager, parent)
        self.file_operations_window = None
        
    def showFileOperations(self, operation_type='encrypt'):
        """Show file operations window
        
        Args:
            operation_type (str): 'encrypt' or 'decrypt' to show specific tab
        """
        if not self.validateAuthentication():
            return
            
        try:
            # Create window if it doesn't exist
            if self.file_operations_window is None:
                self.file_operations_window = FileOperationsWindow(
                    self.session_manager, 
                    self.parent()
                )
            
            # Show appropriate tab
            if operation_type == 'encrypt':
                self.file_operations_window.showEncryptTab()
            elif operation_type == 'decrypt':
                self.file_operations_window.showDecryptTab()
            else:
                self.file_operations_window.show()
                
        except Exception as e:
            self.handleError("File Operations Error", f"Failed to open file operations: {e}")
            
    def showEncryptDialog(self):
        """Show file encryption interface"""
        self.showFileOperations('encrypt')
        
    def showDecryptDialog(self):
        """Show file decryption interface"""
        self.showFileOperations('decrypt')
        
    def getValidRecipients(self):
        """Get list of valid recipients for encryption
        
        Returns:
            tuple: (success, recipients_list or error_message)
        """
        if not self.validateAuthentication():
            return False, "User not authenticated"
            
        try:
            from modules.public_key_manager import PublicKeyManager
            from modules.database import db
            from modules.logger import security_logger
            
            key_manager = PublicKeyManager(
                self.session_manager.current_user['email'],
                db,
                security_logger
            )
            
            return key_manager.get_valid_recipients_for_encryption()
            
        except Exception as e:
            return False, f"Failed to load recipients: {e}"
            
    def validateFileForEncryption(self, file_path):
        """Validate if file can be encrypted
        
        Args:
            file_path (str): Path to file to validate
            
        Returns:
            tuple: (is_valid, message, file_info)
        """
        try:
            from pathlib import Path
            
            file_obj = Path(file_path)
            
            if not file_obj.exists():
                return False, "File does not exist", None
                
            if not file_obj.is_file():
                return False, "Selected path is not a file", None
                
            file_size = file_obj.stat().st_size
            
            if file_size == 0:
                return False, "Cannot encrypt empty file", None
                
            # Check for large file
            from modules.file_crypto import FileCrypto
            crypto = FileCrypto()
            is_large = crypto.is_large_file(file_path)
            
            file_info = {
                'size': file_size,
                'is_large': is_large,
                'name': file_obj.name,
                'extension': file_obj.suffix
            }
            
            return True, "File is valid for encryption", file_info
            
        except Exception as e:
            return False, f"File validation error: {e}", None
            
    def validateFileForDecryption(self, file_path):
        """Validate if file can be decrypted
        
        Args:
            file_path (str): Path to encrypted file to validate
            
        Returns:
            tuple: (is_valid, message, file_info)
        """
        try:
            from pathlib import Path
            
            file_obj = Path(file_path)
            
            if not file_obj.exists():
                return False, "File does not exist", None
                
            if not file_obj.is_file():
                return False, "Selected path is not a file", None
                
            file_size = file_obj.stat().st_size
            
            if file_size == 0:
                return False, "Cannot decrypt empty file", None
                
            # Check if it looks like an encrypted file
            if not file_obj.suffix.lower() == '.enc':
                return False, "File does not appear to be encrypted (.enc extension expected)", None
                
            file_info = {
                'size': file_size,
                'name': file_obj.name,
                'has_key_file': file_obj.with_suffix('.key').exists()
            }
            
            return True, "File appears to be valid for decryption", file_info
            
        except Exception as e:
            return False, f"File validation error: {e}", None 
