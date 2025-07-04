from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QFileDialog, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QFont
from PIL import Image, ImageQt
import base64
import io
import os
from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes

class QRGenerationWorker(QThread):
    finished = pyqtSignal(bool, object)
    
    def __init__(self, user_id, user_email):
        super().__init__()
        self.user_id = user_id
        self.user_email = user_email
    
    def run(self):
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.generate_user_public_key_qr(self.user_id, self.user_email)
            self.finished.emit(success, result)
        except Exception as e:
            self.finished.emit(False, str(e))

class QRGenerationDialog(BaseDialog):
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.current_qr_data = None
        self.current_qr_image = None
        self.worker = None
        
        self.setWindowTitle("Generate QR Code")
        self.setFixedSize(500, 650)
        self.setup_ui()
        self.load_user_info()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # User info group
        user_group = QGroupBox("User Information")
        user_layout = QVBoxLayout(user_group)
        
        self.user_info_label = QLabel()
        font = QFont()
        font.setPointSize(10)
        self.user_info_label.setFont(font)
        user_layout.addWidget(self.user_info_label)
        
        layout.addWidget(user_group)
        
        # QR code display group
        qr_group = QGroupBox("QR Code")
        qr_layout = QVBoxLayout(qr_group)
        
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumHeight(300)
        self.qr_label.setStyleSheet("""
            QLabel {
                border: 2px dashed #cccccc;
                background-color: #f9f9f9;
                color: #666666;
            }
        """)
        self.qr_label.setText("Click 'Generate QR Code' to create your public key QR code")
        qr_layout.addWidget(self.qr_label)
        
        layout.addWidget(qr_group)
        
        # QR data display group
        data_group = QGroupBox("QR Code Data")
        data_layout = QVBoxLayout(data_group)
        
        self.data_display = QTextEdit()
        self.data_display.setMaximumHeight(80)
        self.data_display.setReadOnly(True)
        self.data_display.setPlainText("QR code data will appear here after generation")
        data_layout.addWidget(self.data_display)
        
        layout.addWidget(data_group)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("Generate QR Code")
        self.generate_button.setMinimumHeight(40)
        self.generate_button.clicked.connect(self.generate_qr_code)
        button_layout.addWidget(self.generate_button)
        
        self.save_button = QPushButton("Save QR Code")
        self.save_button.setMinimumHeight(40)
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_qr_code)
        button_layout.addWidget(self.save_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.setMinimumHeight(40)
        self.close_button.clicked.connect(self.accept)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
    
    def load_user_info(self):
        user = self.session_manager.get_current_user()
        if user:
            user_text = f"""Email: {user['email']}
Name: {user['name']}
Phone: {user['phone']}
Registration: {user.get('created_at', 'N/A')}"""
            self.user_info_label.setText(user_text)
    
    def generate_qr_code(self):
        user = self.session_manager.get_current_user()
        if not user:
            MessageBoxes.show_error(self, "Error", "No user session found")
            return
        
        self.generate_button.setEnabled(False)
        self.status_label.setText("Generating QR code...")
        
        self.worker = QRGenerationWorker(user['user_id'], user['email'])
        self.worker.finished.connect(self.on_generation_finished)
        self.worker.start()
    
    def on_generation_finished(self, success, result):
        self.generate_button.setEnabled(True)
        
        if success:
            self.current_qr_data = result
            self.display_qr_code(result)
            self.save_button.setEnabled(True)
            self.status_label.setText("QR code generated successfully!")
        else:
            MessageBoxes.show_error(self, "Generation Failed", f"Failed to generate QR code:\n{result}")
            self.status_label.setText("QR code generation failed")
    
    def display_qr_code(self, qr_data):
        try:
            # Convert base64 QR code to QPixmap
            qr_base64 = qr_data['qr_code_base64']
            qr_bytes = base64.b64decode(qr_base64)
            
            # Create PIL image and convert to Qt
            pil_image = Image.open(io.BytesIO(qr_bytes))
            qt_image = ImageQt.ImageQt(pil_image)
            pixmap = QPixmap.fromImage(qt_image)
            
            # Scale pixmap to fit label while maintaining aspect ratio
            scaled_pixmap = pixmap.scaled(
                self.qr_label.size(), 
                Qt.KeepAspectRatio, 
                Qt.SmoothTransformation
            )
            
            self.qr_label.setPixmap(scaled_pixmap)
            self.current_qr_image = pixmap
            
            # Display QR data
            display_data = f"""Email: {qr_data['email']}
Creation Date: {qr_data['creation_date']}
Public Key: {qr_data['public_key'][:50]}..."""
            self.data_display.setPlainText(display_data)
            
        except Exception as e:
            MessageBoxes.show_error(self, "Display Error", f"Failed to display QR code:\n{str(e)}")
    
    def save_qr_code(self):
        if not self.current_qr_data or not self.current_qr_image:
            MessageBoxes.show_error(self, "Error", "No QR code to save")
            return
        
        try:
            user = self.session_manager.get_current_user()
            default_filename = f"qr_code_{user['email'].replace('@', '_').replace('.', '_')}.png"
            
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Save QR Code", 
                default_filename,
                "PNG Files (*.png);;All Files (*)"
            )
            
            if filename:
                success = self.current_qr_image.save(filename, 'PNG')
                if success:
                    MessageBoxes.show_info(self, "Success", f"QR code saved to:\n{filename}")
                    self.status_label.setText(f"QR code saved to {os.path.basename(filename)}")
                else:
                    MessageBoxes.show_error(self, "Save Failed", "Failed to save QR code image")
        
        except Exception as e:
            MessageBoxes.show_error(self, "Save Error", f"Failed to save QR code:\n{str(e)}")
    
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        event.accept() 
