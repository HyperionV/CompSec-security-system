"""
File Dialog Utilities
Standardized file dialogs for the application
"""

import os
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtCore import QDir

class FileDialogs:
    """Standardized file dialogs for the application"""
    
    @staticmethod
    def get_open_filename(parent, title="Open File", start_dir=None, file_filter="All Files (*)"):
        """Get filename for opening"""
        if start_dir is None:
            start_dir = os.getcwd()
            
        filename, _ = QFileDialog.getOpenFileName(
            parent, title, start_dir, file_filter
        )
        return filename if filename else None
    
    @staticmethod
    def get_save_filename(parent, title="Save File", start_dir=None, file_filter="All Files (*)", default_suffix=None):
        """Get filename for saving"""
        if start_dir is None:
            start_dir = os.getcwd()
            
        filename, _ = QFileDialog.getSaveFileName(
            parent, title, start_dir, file_filter
        )
        
        if filename and default_suffix:
            if not filename.endswith(default_suffix):
                filename += default_suffix
                
        return filename if filename else None
    
    @staticmethod
    def get_directory(parent, title="Select Directory", start_dir=None):
        """Get directory path"""
        if start_dir is None:
            start_dir = os.getcwd()
            
        directory = QFileDialog.getExistingDirectory(
            parent, title, start_dir, QFileDialog.ShowDirsOnly
        )
        return directory if directory else None
    
    @staticmethod
    def get_file_to_encrypt(parent):
        """Get file to encrypt"""
        return FileDialogs.get_open_filename(
            parent,
            "Select File to Encrypt",
            file_filter="All Files (*)"
        )
    
    @staticmethod
    def get_file_to_decrypt(parent):
        """Get encrypted file to decrypt"""
        return FileDialogs.get_open_filename(
            parent,
            "Select Encrypted File",
            file_filter="Encrypted Files (*.enc);;All Files (*)"
        )
    
    @staticmethod
    def get_key_file(parent):
        """Get key file"""
        return FileDialogs.get_open_filename(
            parent,
            "Select Key File",
            file_filter="Key Files (*.key);;All Files (*)"
        )
    
    @staticmethod
    def get_file_to_sign(parent):
        """Get file to sign"""
        return FileDialogs.get_open_filename(
            parent,
            "Select File to Sign",
            file_filter="All Files (*)"
        )
    
    @staticmethod
    def get_signature_file(parent):
        """Get signature file"""
        return FileDialogs.get_open_filename(
            parent,
            "Select Signature File",
            file_filter="Signature Files (*.sig);;All Files (*)"
        )
    
    @staticmethod
    def get_qr_image_file(parent):
        """Get QR code image file"""
        return FileDialogs.get_open_filename(
            parent,
            "Select QR Code Image",
            file_filter="Image Files (*.png *.jpg *.jpeg *.bmp);;All Files (*)"
        )
    
    @staticmethod
    def save_encrypted_file(parent, original_filename):
        """Save encrypted file"""
        base_name = os.path.splitext(os.path.basename(original_filename))[0]
        default_name = f"{base_name}.enc"
        
        return FileDialogs.get_save_filename(
            parent,
            "Save Encrypted File",
            start_dir=os.path.join(os.getcwd(), "data", "encrypted", default_name),
            file_filter="Encrypted Files (*.enc);;All Files (*)",
            default_suffix=".enc"
        )
    
    @staticmethod
    def save_decrypted_file(parent, original_filename=None):
        """Save decrypted file"""
        if original_filename:
            default_name = original_filename
        else:
            default_name = "decrypted_file"
            
        return FileDialogs.get_save_filename(
            parent,
            "Save Decrypted File",
            start_dir=os.path.join(os.getcwd(), "data", "decrypted", default_name),
            file_filter="All Files (*)"
        )
    
    @staticmethod
    def save_signature_file(parent, original_filename):
        """Save signature file"""
        base_name = os.path.splitext(os.path.basename(original_filename))[0]
        default_name = f"{base_name}.sig"
        
        return FileDialogs.get_save_filename(
            parent,
            "Save Signature File",
            start_dir=os.path.join(os.getcwd(), "data", "signatures", default_name),
            file_filter="Signature Files (*.sig);;All Files (*)",
            default_suffix=".sig"
        )
    
    @staticmethod
    def save_qr_code(parent, default_name="qr_code.png"):
        """Save QR code image"""
        return FileDialogs.get_save_filename(
            parent,
            "Save QR Code",
            start_dir=os.path.join(os.getcwd(), "data", "qr_codes", default_name),
            file_filter="PNG Images (*.png);;All Files (*)",
            default_suffix=".png"
        )
    
    @staticmethod
    def get_multiple_files(parent, title="Select Files", file_filter="All Files (*)"):
        """Get multiple files"""
        filenames, _ = QFileDialog.getOpenFileNames(
            parent, title, os.getcwd(), file_filter
        )
        return filenames if filenames else []
    
    # Alias methods for consistency with dialog usage
    @staticmethod
    def getEncryptFile(parent):
        """Alias for get_file_to_encrypt"""
        return FileDialogs.get_file_to_encrypt(parent)
    
    @staticmethod
    def getDecryptFile(parent):
        """Alias for get_file_to_decrypt"""
        return FileDialogs.get_file_to_decrypt(parent)
    
    @staticmethod
    def getKeyFile(parent):
        """Alias for get_key_file"""
        return FileDialogs.get_key_file(parent) 
