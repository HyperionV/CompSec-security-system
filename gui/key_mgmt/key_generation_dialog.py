from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QProgressBar, QTextEdit,
                             QComboBox, QCheckBox, QFormLayout, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from ..base import BaseDialog
from ..utils import MessageBoxes

class KeyGenerationWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str, dict)
    
    def __init__(self, key_manager, user_id, passphrase):
        super().__init__()
        self.key_manager = key_manager
        self.user_id = user_id
        self.passphrase = passphrase
    
    def run(self):
        try:
            self.progress.emit(20)
            
            # Generate RSA key pair
            success, message, result = self.key_manager.create_user_keys(
                self.user_id, self.passphrase
            )
            
            self.progress.emit(100)
            self.finished.emit(success, message, result or {})
            
        except Exception as e:
            self.progress.emit(100)
            self.finished.emit(False, f"Key generation failed: {str(e)}", {})

class KeyGenerationDialog(BaseDialog):
    def __init__(self, key_manager, user_id, parent=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.user_id = user_id
        self.worker = None
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Generate RSA Key Pair")
        self.setFixedSize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Generate New RSA Key Pair")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Key parameters group
        params_group = QGroupBox("Key Parameters")
        params_layout = QFormLayout(params_group)
        
        # Key size selection
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["2048 bits (Recommended)", "4096 bits (High Security)"])
        self.key_size_combo.setCurrentIndex(0)
        params_layout.addRow("Key Size:", self.key_size_combo)
        
        layout.addWidget(params_group)
        
        # Passphrase group
        passphrase_group = QGroupBox("Passphrase Protection")
        passphrase_layout = QFormLayout(passphrase_group)
        
        # Passphrase input
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setPlaceholderText("Enter passphrase to protect private key")
        passphrase_layout.addRow("Passphrase:", self.passphrase_input)
        
        # Confirm passphrase
        self.confirm_passphrase_input = QLineEdit()
        self.confirm_passphrase_input.setEchoMode(QLineEdit.Password)
        self.confirm_passphrase_input.setPlaceholderText("Confirm passphrase")
        passphrase_layout.addRow("Confirm:", self.confirm_passphrase_input)
        
        # Show passphrase checkbox
        self.show_passphrase_check = QCheckBox("Show passphrase")
        self.show_passphrase_check.toggled.connect(self.toggle_passphrase_visibility)
        passphrase_layout.addRow("", self.show_passphrase_check)
        
        layout.addWidget(passphrase_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)
        
        # Results area
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(100)
        self.results_text.setVisible(False)
        layout.addWidget(self.results_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("Generate Key Pair")
        self.generate_button.clicked.connect(self.generate_keys)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        self.close_button.setVisible(False)
        
        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        
        # Connect passphrase validation
        self.passphrase_input.textChanged.connect(self.validate_input)
        self.confirm_passphrase_input.textChanged.connect(self.validate_input)
        
        self.validate_input()
    
    def toggle_passphrase_visibility(self, checked):
        mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.passphrase_input.setEchoMode(mode)
        self.confirm_passphrase_input.setEchoMode(mode)
    
    def validate_input(self):
        passphrase = self.passphrase_input.text()
        confirm_passphrase = self.confirm_passphrase_input.text()
        
        # Basic validation
        valid = (len(passphrase) >= 8 and 
                passphrase == confirm_passphrase and 
                passphrase.strip() != "")
        
        self.generate_button.setEnabled(valid)
        
        if passphrase and len(passphrase) < 8:
            self.status_label.setText("Passphrase must be at least 8 characters")
            self.status_label.setStyleSheet("color: #dc3545;")
            self.status_label.setVisible(True)
        elif passphrase and confirm_passphrase and passphrase != confirm_passphrase:
            self.status_label.setText("Passphrases do not match")
            self.status_label.setStyleSheet("color: #dc3545;")
            self.status_label.setVisible(True)
        else:
            self.status_label.setVisible(False)
    
    def generate_keys(self):
        passphrase = self.passphrase_input.text()
        
        if not passphrase or len(passphrase) < 8:
            MessageBoxes.warning(self, "Invalid Input", "Please enter a passphrase of at least 8 characters.")
            return
        
        if passphrase != self.confirm_passphrase_input.text():
            MessageBoxes.warning(self, "Passphrase Mismatch", "Passphrases do not match.")
            return
        
        # Disable UI elements
        self.generate_button.setEnabled(False)
        self.passphrase_input.setEnabled(False)
        self.confirm_passphrase_input.setEnabled(False)
        self.key_size_combo.setEnabled(False)
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.status_label.setText("Generating RSA key pair...")
        self.status_label.setStyleSheet("color: #007bff;")
        self.status_label.setVisible(True)
        
        # Start worker thread
        self.worker = KeyGenerationWorker(self.key_manager, self.user_id, passphrase)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_generation_finished)
        self.worker.start()
    
    def on_generation_finished(self, success, message, result):
        # Hide progress
        self.progress_bar.setVisible(False)
        
        if success:
            self.status_label.setText("✓ Key pair generated successfully!")
            self.status_label.setStyleSheet("color: #28a745;")
            
            # Show results
            self.results_text.setText(f"""
Key Generation Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ RSA Key Pair Generated Successfully
• Key Size: 2048 bits
• Algorithm: RSA-OAEP with SHA-256
• Encryption: AES-256-GCM with PBKDF2
• Expiry: 90 days from creation

Your private key has been encrypted and stored securely.
The public key is now available for file encryption operations.

⚠️ IMPORTANT: Remember your passphrase! It cannot be recovered.
            """.strip())
            self.results_text.setVisible(True)
            
            # Switch buttons
            self.cancel_button.setVisible(False)
            self.close_button.setVisible(True)
            
        else:
            self.status_label.setText(f"✗ Key generation failed: {message}")
            self.status_label.setStyleSheet("color: #dc3545;")
            
            # Re-enable form
            self.generate_button.setEnabled(True)
            self.passphrase_input.setEnabled(True)
            self.confirm_passphrase_input.setEnabled(True)
            self.key_size_combo.setEnabled(True)
        
        # Clean up worker
        if self.worker:
            self.worker.deleteLater()
            self.worker = None 
