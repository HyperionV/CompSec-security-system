from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
                            QLineEdit, QPushButton, QComboBox, QRadioButton, 
                            QButtonGroup, QProgressBar, QTextEdit, QGroupBox, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtGui import QFont

from ..base.base_dialog import BaseDialog
from ..utils.file_dialogs import FileDialogs
from ..utils.message_boxes import MessageBoxes
from .encryption_worker import EncryptionWorker

class FileEncryptDialog(BaseDialog):
    """Dialog for encrypting files with recipient selection and format options"""
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.selected_file = None
        self.encryption_worker = None
        self.encryption_thread = None
        self.setupUI()
        self.connectSignals()
        self.loadRecipients()
        
    def setupUI(self):
        self.setWindowTitle("Encrypt File")
        self.setFixedSize(500, 600)
        
        layout = QVBoxLayout()
        
        # File Selection Section
        file_group = QGroupBox("File Selection")
        file_layout = QGridLayout()
        
        file_layout.addWidget(QLabel("Select File:"), 0, 0)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText("Choose file to encrypt...")
        file_layout.addWidget(self.file_path_edit, 0, 1)
        
        self.browse_file_button = QPushButton("Browse")
        self.browse_file_button.setFixedWidth(80)
        file_layout.addWidget(self.browse_file_button, 0, 2)
        
        # File info display
        self.file_info_label = QLabel("No file selected")
        self.file_info_label.setStyleSheet("color: #666; font-style: italic;")
        file_layout.addWidget(self.file_info_label, 1, 1, 1, 2)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Recipient Selection Section
        recipient_group = QGroupBox("Recipient Selection")
        recipient_layout = QVBoxLayout()
        
        recipient_layout.addWidget(QLabel("Select Recipient:"))
        self.recipient_combo = QComboBox()
        self.recipient_combo.setMinimumHeight(30)
        recipient_layout.addWidget(self.recipient_combo)
        
        self.refresh_recipients_button = QPushButton("Refresh Recipients")
        self.refresh_recipients_button.setFixedHeight(25)
        recipient_layout.addWidget(self.refresh_recipients_button)
        
        recipient_group.setLayout(recipient_layout)
        layout.addWidget(recipient_group)
        
        # Format Options Section
        format_group = QGroupBox("Output Format")
        format_layout = QVBoxLayout()
        
        self.format_group = QButtonGroup()
        
        self.combined_radio = QRadioButton("Combined .enc file (recommended)")
        self.combined_radio.setChecked(True)
        self.format_group.addButton(self.combined_radio, 0)
        format_layout.addWidget(self.combined_radio)
        
        self.separate_radio = QRadioButton("Separate .enc + .key files")
        self.format_group.addButton(self.separate_radio, 1)
        format_layout.addWidget(self.separate_radio)
        
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)
        
        # Progress Section
        progress_group = QGroupBox("Encryption Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to encrypt")
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
        
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setFixedSize(120, 35)
        self.encrypt_button.setEnabled(False)
        button_layout.addWidget(self.encrypt_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.setFixedSize(80, 35)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def connectSignals(self):
        self.browse_file_button.clicked.connect(self.selectFile)
        self.recipient_combo.currentTextChanged.connect(self.validateForm)
        self.refresh_recipients_button.clicked.connect(self.loadRecipients)
        self.encrypt_button.clicked.connect(self.startEncryption)
        self.close_button.clicked.connect(self.reject)
        
    def selectFile(self):
        file_path = FileDialogs.getEncryptFile(self)
        if file_path:
            self.selected_file = file_path
            self.file_path_edit.setText(file_path)
            
            # Update file info
            from pathlib import Path
            file_obj = Path(file_path)
            file_size = file_obj.stat().st_size
            
            if file_size > 5 * 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB (Large File)"
                self.file_info_label.setText(f"Size: {size_str}")
                self.file_info_label.setStyleSheet("color: #ff6600; font-weight: bold;")
            else:
                size_str = f"{file_size / 1024:.1f} KB"
                self.file_info_label.setText(f"Size: {size_str}")
                self.file_info_label.setStyleSheet("color: #666;")
                
            self.validateForm()
            
    def loadRecipients(self):
        try:
            from modules.public_key_manager import PublicKeyManager
            from modules.database import db
            from modules.logger import security_logger
            
            key_manager = PublicKeyManager(
                self.session_manager.current_user['email'],
                db,
                security_logger
            )
            
            success, recipients = key_manager.get_valid_recipients_for_encryption()
            
            self.recipient_combo.clear()
            if success and recipients:
                self.recipient_combo.addItem("Select recipient...", None)
                for recipient in recipients:
                    self.recipient_combo.addItem(recipient['display'], recipient)
                self.status_label.setText(f"Found {len(recipients)} available recipients")
            else:
                self.recipient_combo.addItem("No recipients available", None)
                self.status_label.setText("No valid public keys found")
                
        except Exception as e:
            MessageBoxes.showError(self, "Error", f"Failed to load recipients: {e}")
            
    def validateForm(self):
        has_file = self.selected_file is not None
        has_recipient = (self.recipient_combo.currentData() is not None and 
                        self.recipient_combo.currentIndex() > 0)
        
        self.encrypt_button.setEnabled(has_file and has_recipient)
        
        if has_file and has_recipient:
            self.status_label.setText("Ready to encrypt")
            self.status_label.setStyleSheet("color: #0c7d0c;")
        elif not has_file:
            self.status_label.setText("Please select a file to encrypt")
            self.status_label.setStyleSheet("color: #666;")
        elif not has_recipient:
            self.status_label.setText("Please select a recipient")
            self.status_label.setStyleSheet("color: #666;")
            
    def startEncryption(self):
        if not self.selected_file or self.recipient_combo.currentData() is None:
            return
            
        recipient_data = self.recipient_combo.currentData()
        recipient_email = recipient_data['email']
        
        output_format = 'combined' if self.combined_radio.isChecked() else 'separate'
        
        # Update UI for encryption process
        self.encrypt_button.setEnabled(False)
        self.browse_file_button.setEnabled(False)
        self.recipient_combo.setEnabled(False)
        self.combined_radio.setEnabled(False)
        self.separate_radio.setEnabled(False)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_text.setVisible(True)
        self.log_text.clear()
        
        self.status_label.setText("Starting encryption...")
        self.status_label.setStyleSheet("color: #0066cc;")
        
        # Create and start worker thread
        self.encryption_thread = QThread()
        self.encryption_worker = EncryptionWorker(
            file_path=self.selected_file,
            recipient_email=recipient_email,
            user_id=self.session_manager.current_user['id'],
            output_format=output_format
        )
        self.encryption_worker.moveToThread(self.encryption_thread)
        
        # Connect signals
        self.encryption_thread.started.connect(self.encryption_worker.encrypt)
        self.encryption_worker.progress.connect(self.updateProgress)
        self.encryption_worker.log_message.connect(self.appendLog)
        self.encryption_worker.finished.connect(self.encryptionFinished)
        self.encryption_worker.error.connect(self.encryptionError)
        
        # Cleanup
        self.encryption_worker.finished.connect(self.encryption_thread.quit)
        self.encryption_worker.finished.connect(self.encryption_worker.deleteLater)
        self.encryption_thread.finished.connect(self.encryption_thread.deleteLater)
        
        self.encryption_thread.start()
        
    def updateProgress(self, value):
        self.progress_bar.setValue(value)
        
    def appendLog(self, message):
        self.log_text.append(message)
        
    def encryptionFinished(self, success, message, result_info):
        if success:
            self.status_label.setText("Encryption completed successfully!")
            self.status_label.setStyleSheet("color: #0c7d0c; font-weight: bold;")
            
            # Show success message with details
            if result_info:
                details = f"Encrypted file saved as: {result_info.get('output_file', 'N/A')}"
                if result_info.get('key_file'):
                    details += f"\nKey file saved as: {result_info['key_file']}"
                MessageBoxes.showInfo(self, "Encryption Complete", details)
        else:
            self.status_label.setText(f"Encryption failed: {message}")
            self.status_label.setStyleSheet("color: #cc0000;")
            MessageBoxes.showError(self, "Encryption Failed", message)
        
        self.resetForm()
        
    def encryptionError(self, error_message):
        self.status_label.setText(f"Error: {error_message}")
        self.status_label.setStyleSheet("color: #cc0000;")
        MessageBoxes.showError(self, "Encryption Error", error_message)
        self.resetForm()
        
    def resetForm(self):
        self.encrypt_button.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.recipient_combo.setEnabled(True)
        self.combined_radio.setEnabled(True)
        self.separate_radio.setEnabled(True)
        self.progress_bar.setValue(0) 
