from PyQt5.QtCore import QObject, pyqtSignal, QThread
from modules.digital_signature import DigitalSignature

class SigningWorker(QObject):
    progress = pyqtSignal(str)
    signed = pyqtSignal(str, str)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, user_email, key_manager, database, logger):
        super().__init__()
        self.user_email = user_email
        self.key_manager = key_manager
        self.database = database
        self.logger = logger
        self.file_path = None
        self.passphrase = None

    def set_signing_data(self, file_path, passphrase):
        self.file_path = file_path
        self.passphrase = passphrase

    def run(self):
        try:
            self.progress.emit("Initializing digital signature...")
            
            digital_signature = DigitalSignature(
                self.user_email,
                self.key_manager,
                self.database,
                self.logger
            )
            
            self.progress.emit("Signing file...")
            success, result = digital_signature.sign_file(self.file_path, self.passphrase)
            
            if success:
                self.progress.emit("File signed successfully!")
                self.signed.emit(self.file_path, result)
            else:
                self.error.emit(result)
                
        except Exception as e:
            self.error.emit(f"Signing error: {str(e)}")
        finally:
            self.finished.emit() 
