from PyQt5.QtWidgets import QTabWidget, QVBoxLayout
from PyQt5.QtCore import pyqtSignal

from ..base.base_window import BaseWindow
from .file_encrypt_dialog import FileEncryptDialog
from .file_decrypt_dialog import FileDecryptDialog

class FileOperationsWindow(BaseWindow):
    """Main window for file encryption and decryption operations"""
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.setupUI()
        
    def setupUI(self):
        self.setWindowTitle("File Operations")
        self.setFixedSize(520, 650)
        
        layout = QVBoxLayout()
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create encrypt and decrypt tabs
        self.encrypt_widget = FileEncryptDialog(self.session_manager)
        self.decrypt_widget = FileDecryptDialog(self.session_manager)
        
        # Remove dialog-specific styling from the components
        self.encrypt_widget.setWindowFlags(self.encrypt_widget.windowFlags() & ~self.encrypt_widget.windowFlags())
        self.decrypt_widget.setWindowFlags(self.decrypt_widget.windowFlags() & ~self.decrypt_widget.windowFlags())
        
        # Add tabs
        self.tab_widget.addTab(self.encrypt_widget, "Encrypt Files")
        self.tab_widget.addTab(self.decrypt_widget, "Decrypt Files")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
        
        # Connect close signals to hide window instead of closing
        self.encrypt_widget.close_button.clicked.disconnect()
        self.decrypt_widget.close_button.clicked.disconnect()
        self.encrypt_widget.close_button.clicked.connect(self.hide)
        self.decrypt_widget.close_button.clicked.connect(self.hide)
        
    def showEncryptTab(self):
        """Show the window with encrypt tab active"""
        self.tab_widget.setCurrentIndex(0)
        self.show()
        self.raise_()
        self.activateWindow()
        
    def showDecryptTab(self):
        """Show the window with decrypt tab active"""
        self.tab_widget.setCurrentIndex(1)
        self.show()
        self.raise_()
        self.activateWindow() 
