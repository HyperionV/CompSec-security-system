from PyQt5.QtCore import QObject, pyqtSignal
from modules.signature_verification import SignatureVerification

class VerificationWorker(QObject):
    progress = pyqtSignal(str)
    verified = pyqtSignal(bool, str, dict)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, user_email, database, logger):
        super().__init__()
        self.user_email = user_email
        self.database = database
        self.logger = logger
        self.file_path = None
        self.signature_path = None

    def set_verification_data(self, file_path, signature_path=None):
        self.file_path = file_path
        self.signature_path = signature_path

    def run(self):
        try:
            self.progress.emit("Initializing signature verification...")
            
            signature_verification = SignatureVerification(
                self.user_email,
                self.database,
                self.logger
            )
            
            self.progress.emit("Verifying signature...")
            result = signature_verification.verify_signature(self.file_path, self.signature_path)
            
            if len(result) == 3:
                success, message, metadata = result
                self.verified.emit(success, message, metadata if success else {})
            else:
                success, message = result
                self.verified.emit(success, message, {})
                
        except Exception as e:
            self.error.emit(f"Verification error: {str(e)}")
        finally:
            self.finished.emit() 
