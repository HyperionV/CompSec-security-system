import os
from gui.controllers.base_controller import BaseController
from gui.digital_sig.digital_signature_window import DigitalSignatureWindow
from gui.utils.message_boxes import MessageBoxes

class DigitalSignatureController(BaseController):
    def __init__(self, session_manager):
        super().__init__(session_manager)
        self.digital_signature_window = None

    def showDigitalSignatureOperations(self):
        if not self.validateAuthentication():
            return

        if not self.digital_signature_window:
            self.digital_signature_window = DigitalSignatureWindow(self.session_manager)
        
        self.digital_signature_window.show()

    def showFileSign(self):
        if not self.validateAuthentication():
            return

        if not self.digital_signature_window:
            self.digital_signature_window = DigitalSignatureWindow(self.session_manager)
        
        self.digital_signature_window.showSignTab()

    def showSignatureVerify(self):
        if not self.validateAuthentication():
            return

        if not self.digital_signature_window:
            self.digital_signature_window = DigitalSignatureWindow(self.session_manager)
        
        self.digital_signature_window.showVerifyTab()

    def validateFileForSigning(self, file_path):
        if not file_path or not os.path.exists(file_path):
            return False, "Invalid file path"
        
        if not os.path.isfile(file_path):
            return False, "Path is not a file"
        
        if os.path.getsize(file_path) == 0:
            return False, "File is empty"
        
        return True, "File is valid for signing"

    def validateFileForVerification(self, file_path, signature_path=None):
        # Validate original file
        if not file_path or not os.path.exists(file_path):
            return False, "Invalid original file path"
        
        if not os.path.isfile(file_path):
            return False, "Original file path is not a file"
        
        # Validate signature file
        if signature_path:
            if not os.path.exists(signature_path):
                return False, "Signature file does not exist"
            
            if not os.path.isfile(signature_path):
                return False, "Signature path is not a file"
        else:
            # Check for auto-detected signature file
            auto_sig_path = file_path + ".sig"
            if not os.path.exists(auto_sig_path):
                return False, "No signature file found and none specified"
        
        return True, "Files are valid for verification"

    def getSignatureFileInfo(self, file_path):
        signature_path = file_path + ".sig"
        
        if os.path.exists(signature_path):
            return {
                'exists': True,
                'path': signature_path,
                'filename': os.path.basename(signature_path),
                'size': os.path.getsize(signature_path)
            }
        else:
            return {
                'exists': False,
                'path': signature_path,
                'filename': os.path.basename(signature_path),
                'size': 0
            } 
