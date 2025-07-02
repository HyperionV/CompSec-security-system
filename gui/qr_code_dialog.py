import sys
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QMessageBox, QFrame, QFileDialog)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap
import os

class QRCodeDialog(QDialog):
    def __init__(self, qr_image_path, user_email, secret, parent=None):
        super().__init__(parent)
        self.qr_image_path = qr_image_path
        self.user_email = user_email
        self.secret = secret
        self.qr_pixmap = None
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("TOTP Setup - QR Code")
        self.setFixedSize(450, 550)
        self.setModal(True)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("🔐 TOTP Authentication Setup")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)
        
        # Instructions
        instruction_label = QLabel(f"Scan this QR code with Google Authenticator\nor any TOTP-compatible app for:\n{self.user_email}")
        instruction_label.setAlignment(Qt.AlignCenter)
        instruction_label.setWordWrap(True)
        layout.addWidget(instruction_label)
        
        # QR Code Display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet("""
            QLabel {
                border: 2px solid #ddd;
                border-radius: 10px;
                padding: 20px;
                background-color: white;
            }
        """)
        
        # Load and display QR code
        self.load_qr_code()
        layout.addWidget(self.qr_label)
        
        # Secret key info
        secret_frame = QFrame()
        secret_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        secret_layout = QVBoxLayout()
        
        secret_title = QLabel("Manual Entry Key:")
        secret_title.setFont(QFont("Arial", 10, QFont.Bold))
        secret_layout.addWidget(secret_title)
        
        secret_value = QLabel(self.secret)
        secret_value.setFont(QFont("Courier", 10))
        secret_value.setWordWrap(True)
        secret_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        secret_value.setStyleSheet("color: #333; padding: 5px;")
        secret_layout.addWidget(secret_value)
        
        secret_frame.setLayout(secret_layout)
        layout.addWidget(secret_frame)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignCenter)
        
        save_button = QPushButton("Save QR Code")
        save_button.clicked.connect(self.save_qr_code)
        save_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        button_layout.addWidget(save_button)
        
        self.done_button = QPushButton("Setup Complete")
        self.done_button.clicked.connect(self.accept)
        self.done_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(self.done_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
        # Help text
        help_label = QLabel("💡 After scanning, test your TOTP app to ensure it generates 6-digit codes")
        help_label.setAlignment(Qt.AlignCenter)
        help_label.setStyleSheet("color: #FF9800; font-size: 11px; font-style: italic;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        self.setLayout(layout)
        
    def load_qr_code(self):
        """Load and display the QR code image"""
        try:
            if os.path.exists(self.qr_image_path):
                self.qr_pixmap = QPixmap(self.qr_image_path)
                if not self.qr_pixmap.isNull():
                    # Scale the QR code to fit nicely in the dialog
                    scaled_pixmap = self.qr_pixmap.scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.qr_label.setPixmap(scaled_pixmap)
                else:
                    self.show_error("Failed to load QR code image")
            else:
                self.show_error("QR code file not found")
        except Exception as e:
            self.show_error(f"Error loading QR code: {str(e)}")
    
    def save_qr_code(self):
        """Save QR code to user-selected location"""
        try:
            if self.qr_pixmap and not self.qr_pixmap.isNull():
                filename, _ = QFileDialog.getSaveFileName(
                    self,
                    "Save QR Code",
                    f"totp_qr_{self.user_email.replace('@', '_').replace('.', '_')}.png",
                    "PNG Files (*.png);;All Files (*)"
                )
                if filename:
                    if self.qr_pixmap.save(filename, "PNG"):
                        QMessageBox.information(self, "Success", f"QR code saved successfully to:\n{filename}")
                    else:
                        QMessageBox.warning(self, "Error", "Failed to save QR code image")
            else:
                QMessageBox.warning(self, "Error", "No QR code image to save")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving QR code:\n{str(e)}")
    
    def show_error(self, message):
        """Display error message"""
        self.qr_label.setText(f"❌ {message}")
        self.qr_label.setStyleSheet("""
            QLabel {
                border: 2px solid #f44336;
                border-radius: 10px;
                padding: 20px;
                background-color: #ffebee;
                color: #f44336;
            }
        """)

def show_qr_code_dialog(qr_image_path, user_email, secret, parent=None):
    """Show QR code dialog and return True if setup completed, False if cancelled"""
    dialog = QRCodeDialog(qr_image_path, user_email, secret, parent)
    return dialog.exec_() == QDialog.Accepted 