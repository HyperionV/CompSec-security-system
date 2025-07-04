from PyQt5.QtWidgets import QVBoxLayout, QTabWidget
from gui.base.base_window import BaseWindow
from .file_sign_dialog import FileSignDialog
from .signature_verify_dialog import SignatureVerifyDialog

class DigitalSignatureWindow(BaseWindow):
    def __init__(self, session_manager, parent=None):
        super().__init__("Digital Signature Operations", parent)
        self.session_manager = session_manager
        self.setupUI()

    def setupUI(self):
        central_widget = self.getCentralWidget()
        layout = QVBoxLayout()

        # Create tab widget
        self.tab_widget = QTabWidget()

        # Add file signing tab
        self.file_sign_dialog = FileSignDialog(self.session_manager, self)
        self.tab_widget.addTab(self.file_sign_dialog, "Sign Files")

        # Add signature verification tab
        self.signature_verify_dialog = SignatureVerifyDialog(self.session_manager, self)
        self.tab_widget.addTab(self.signature_verify_dialog, "Verify Signatures")

        layout.addWidget(self.tab_widget)
        central_widget.setLayout(layout)
        
        self.resize(800, 700)

    def showSignTab(self):
        self.tab_widget.setCurrentIndex(0)
        self.show()

    def showVerifyTab(self):
        self.tab_widget.setCurrentIndex(1)
        self.show() 
