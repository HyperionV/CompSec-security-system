from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
                            QLineEdit, QPushButton, QProgressBar, QTextEdit, 
                            QGroupBox, QSpacerItem, QSizePolicy, QCheckBox)
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtGui import QFont

from ..base.base_dialog import BaseDialog
from ..utils.file_dialogs import FileDialogs
from ..utils.message_boxes import MessageBoxes
from .decryption_worker import DecryptionWorker

class FileDecryptDialog(BaseDialog):
    """Dialog for decrypting files with automatic format detection"""
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.selected_file = None
        self.key_file = None
        self.decryption_worker = None
        self.decryption_thread = None
        self.setupUI()
        self.connectSignals()
        
    def setupUI(self):
        self.setWindowTitle("Decrypt File")
        self.setFixedSize(500, 550)
        
        layout = QVBoxLayout()
        
        # File Selection Section
        file_group = QGroupBox("File Selection")
        file_layout = QGridLayout()
        
        # Encrypted file selection
        file_layout.addWidget(QLabel("Encrypted File:"), 0, 0)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText("Choose .enc file to decrypt...")
        file_layout.addWidget(self.file_path_edit, 0, 1)
        
        self.browse_file_button = QPushButton("Browse")
        self.browse_file_button.setFixedWidth(80)
        file_layout.addWidget(self.browse_file_button, 0, 2)
        
        # Key file selection (for separate format)
        file_layout.addWidget(QLabel("Key File (if separate):"), 1, 0)
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setReadOnly(True)
        self.key_file_edit.setPlaceholderText("Optional: Choose .key file...")
        file_layout.addWidget(self.key_file_edit, 1, 1)
        
        self.browse_key_button = QPushButton("Browse")
        self.browse_key_button.setFixedWidth(80)
        self.browse_key_button.setEnabled(False)
        file_layout.addWidget(self.browse_key_button, 1, 2)
        
        # File info display
        self.file_info_label = QLabel("No file selected")
        self.file_info_label.setStyleSheet("color: #666; font-style: italic;")
        file_layout.addWidget(self.file_info_label, 2, 1, 1, 2)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Authentication Section
        auth_group = QGroupBox("Authentication")
        auth_layout = QGridLayout()
        
        auth_layout.addWidget(QLabel("Passphrase:"), 0, 0)
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.Password)
        self.passphrase_edit.setPlaceholderText("Enter your passphrase...")
        auth_layout.addWidget(self.passphrase_edit, 0, 1)
        
        self.show_passphrase_check = QCheckBox("Show passphrase")
        auth_layout.addWidget(self.show_passphrase_check, 1, 1)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Progress Section
        progress_group = QGroupBox("Decryption Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to decrypt")
        self.status_label.setStyleSheet("color: #333;")
        progress_layout.addWidget(self.status_label)
        
        # Operation log
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(100)
        self.log_text.setVisible(False)
        progress_layout.addWidget(self.log_text)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setFixedSize(120, 35)
        self.decrypt_button.setEnabled(False)
        button_layout.addWidget(self.decrypt_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.setFixedSize(80, 35)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def connectSignals(self):
        self.browse_file_button.clicked.connect(self.selectEncryptedFile)
        self.browse_key_button.clicked.connect(self.selectKeyFile)
        self.passphrase_edit.textChanged.connect(self.validateForm)
        self.show_passphrase_check.toggled.connect(self.togglePassphraseVisibility)
        self.decrypt_button.clicked.connect(self.startDecryption)
        self.close_button.clicked.connect(self.reject)
        
    def selectEncryptedFile(self):
        file_path = FileDialogs.getDecryptFile(self)
        if file_path:
            self.selected_file = file_path
            self.file_path_edit.setText(file_path)
            
            # Update file info and detect format
            from pathlib import Path
            file_obj = Path(file_path)
            file_size = file_obj.stat().st_size
            
            size_str = f"{file_size / 1024:.1f} KB"
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
                
            self.file_info_label.setText(f"Size: {size_str}")
            self.file_info_label.setStyleSheet("color: #666;")
            
            # Auto-detect format and enable key file selection if needed
            self.detectFileFormat(file_path)
            self.validateForm()
            
    def detectFileFormat(self, file_path):
        """Detect if file is combined format or requires separate key file"""
        try:
            # Simple heuristic: check if there's a corresponding .key file
            from pathlib import Path
            encrypted_path = Path(file_path)
            potential_key_file = encrypted_path.with_suffix('.key')
            
            if potential_key_file.exists():
                self.status_label.setText("Separate format detected - key file found")
                self.key_file_edit.setText(str(potential_key_file))
                self.key_file = str(potential_key_file)
                self.browse_key_button.setEnabled(True)
                self.status_label.setStyleSheet("color: #0066cc;")
            else:
                self.status_label.setText("Combined format detected")
                self.key_file_edit.clear()
                self.key_file = None
                self.browse_key_button.setEnabled(True)  # Still allow manual selection
                self.status_label.setStyleSheet("color: #0c7d0c;")
                
        except Exception:
            self.status_label.setText("File format will be auto-detected")
            self.browse_key_button.setEnabled(True)
            
    def selectKeyFile(self):
        file_path = FileDialogs.getKeyFile(self)
        if file_path:
            self.key_file = file_path
            self.key_file_edit.setText(file_path)
            self.status_label.setText("Key file selected")
            self.validateForm()
            
    def togglePassphraseVisibility(self, checked):
        if checked:
            self.passphrase_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.passphrase_edit.setEchoMode(QLineEdit.Password)
            
    def validateForm(self):
        has_file = self.selected_file is not None
        has_passphrase = len(self.passphrase_edit.text().strip()) > 0
        
        self.decrypt_button.setEnabled(has_file and has_passphrase)
        
        if has_file and has_passphrase:
            self.status_label.setText("Ready to decrypt")
            self.status_label.setStyleSheet("color: #0c7d0c;")
        elif not has_file:
            self.status_label.setText("Please select an encrypted file")
            self.status_label.setStyleSheet("color: #666;")
        elif not has_passphrase:
            self.status_label.setText("Please enter your passphrase")
            self.status_label.setStyleSheet("color: #666;")
            
    def startDecryption(self):
        if not self.selected_file or not self.passphrase_edit.text().strip():
            return
            
        passphrase = self.passphrase_edit.text().strip()
        
        # Update UI for decryption process
        self.decrypt_button.setEnabled(False)
        self.browse_file_button.setEnabled(False)
        self.browse_key_button.setEnabled(False)
        self.passphrase_edit.setEnabled(False)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_text.setVisible(True)
        self.log_text.clear()
        
        self.status_label.setText("Starting decryption...")
        self.status_label.setStyleSheet("color: #0066cc;")
        
        # Create and start worker thread
        self.decryption_thread = QThread()
        self.decryption_worker = DecryptionWorker(
            encrypted_file_path=self.selected_file,
            key_file_path=self.key_file,
            user_id=self.session_manager.current_user['id'],
            passphrase=passphrase
        )
        self.decryption_worker.moveToThread(self.decryption_thread)
        
        # Connect signals
        self.decryption_thread.started.connect(self.decryption_worker.decrypt)
        self.decryption_worker.progress.connect(self.updateProgress)
        self.decryption_worker.log_message.connect(self.appendLog)
        self.decryption_worker.finished.connect(self.decryptionFinished)
        self.decryption_worker.error.connect(self.decryptionError)
        
        # Cleanup
        self.decryption_worker.finished.connect(self.decryption_thread.quit)
        self.decryption_worker.finished.connect(self.decryption_worker.deleteLater)
        self.decryption_thread.finished.connect(self.decryption_thread.deleteLater)
        
        self.decryption_thread.start()
        
    def updateProgress(self, value):
        self.progress_bar.setValue(value)
        
    def appendLog(self, message):
        self.log_text.append(message)
        
    def decryptionFinished(self, success, message, result_info):
        if success:
            self.status_label.setText("Decryption completed successfully!")
            self.status_label.setStyleSheet("color: #0c7d0c; font-weight: bold;")
            
            # Show success message with details
            if result_info:
                details = f"Decrypted file saved as: {result_info.get('output_file', 'N/A')}"
                if result_info.get('sender'):
                    details += f"\nSender: {result_info['sender']}"
                if result_info.get('original_filename'):
                    details += f"\nOriginal filename: {result_info['original_filename']}"
                MessageBoxes.showInfo(self, "Decryption Complete", details)
        else:
            self.status_label.setText(f"Decryption failed: {message}")
            self.status_label.setStyleSheet("color: #cc0000;")
            MessageBoxes.showError(self, "Decryption Failed", message)
        
        self.resetForm()
        
    def decryptionError(self, error_message):
        self.status_label.setText(f"Error: {error_message}")
        self.status_label.setStyleSheet("color: #cc0000;")
        MessageBoxes.showError(self, "Decryption Error", error_message)
        self.resetForm()
        
    def resetForm(self):
        self.decrypt_button.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.browse_key_button.setEnabled(True)
        self.passphrase_edit.setEnabled(True)
        self.progress_bar.setValue(0)
        # Don't clear passphrase for security - user should do that manually 
