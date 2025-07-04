from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QFileDialog, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QFont
from PIL import Image, ImageQt
import os
from ..base.base_dialog import BaseDialog
from ..utils.message_boxes import MessageBoxes

class QRScanWorker(QThread):
    finished = pyqtSignal(bool, object)
    
    def __init__(self, image_path):
        super().__init__()
        self.image_path = image_path
    
    def run(self):
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.read_public_key_qr(self.image_path)
            self.finished.emit(success, result)
        except Exception as e:
            self.finished.emit(False, str(e))

class QRImportWorker(QThread):
    finished = pyqtSignal(bool, object)
    
    def __init__(self, user_id, image_path):
        super().__init__()
        self.user_id = user_id
        self.image_path = image_path
    
    def run(self):
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.import_public_key_from_qr(self.user_id, self.image_path)
            self.finished.emit(success, result)
        except Exception as e:
            self.finished.emit(False, str(e))

class QRScanDialog(BaseDialog):
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.current_image_path = None
        self.scanned_data = None
        self.scan_worker = None
        self.import_worker = None
        
        self.setWindowTitle("Scan QR Code")
        self.setFixedSize(600, 700)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Instructions
        instructions = QLabel("Load a QR code image file to scan and import public key information")
        instructions.setAlignment(Qt.AlignCenter)
        instructions.setStyleSheet("color: #666666; margin: 10px;")
        layout.addWidget(instructions)
        
        # Image load group
        load_group = QGroupBox("Load QR Code Image")
        load_layout = QVBoxLayout(load_group)
        
        load_button_layout = QHBoxLayout()
        self.load_button = QPushButton("Load QR Code Image")
        self.load_button.setMinimumHeight(40)
        self.load_button.clicked.connect(self.load_image)
        load_button_layout.addWidget(self.load_button)
        load_layout.addLayout(load_button_layout)
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("color: #666666; padding: 5px;")
        load_layout.addWidget(self.file_path_label)
        
        layout.addWidget(load_group)
        
        # Image preview group
        preview_group = QGroupBox("Image Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumHeight(200)
        self.image_label.setStyleSheet("""
            QLabel {
                border: 2px dashed #cccccc;
                background-color: #f9f9f9;
                color: #666666;
            }
        """)
        self.image_label.setText("Image preview will appear here")
        preview_layout.addWidget(self.image_label)
        
        layout.addWidget(preview_group)
        
        # Scan controls
        scan_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Scan QR Code")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self.scan_qr_code)
        scan_layout.addWidget(self.scan_button)
        
        layout.addLayout(scan_layout)
        
        # Scanned data group
        data_group = QGroupBox("Scanned QR Code Data")
        data_layout = QVBoxLayout(data_group)
        
        self.data_display = QTextEdit()
        self.data_display.setMaximumHeight(120)
        self.data_display.setReadOnly(True)
        self.data_display.setPlainText("Scanned QR code data will appear here")
        data_layout.addWidget(self.data_display)
        
        layout.addWidget(data_group)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        self.import_button = QPushButton("Import Public Key")
        self.import_button.setMinimumHeight(40)
        self.import_button.setEnabled(False)
        self.import_button.clicked.connect(self.import_public_key)
        action_layout.addWidget(self.import_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.setMinimumHeight(40)
        self.close_button.clicked.connect(self.accept)
        action_layout.addWidget(self.close_button)
        
        layout.addLayout(action_layout)
    
    def load_image(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load QR Code Image",
            "",
            "Image Files (*.png *.jpg *.jpeg *.bmp *.gif);;All Files (*)"
        )
        
        if filename:
            self.current_image_path = filename
            self.file_path_label.setText(f"File: {os.path.basename(filename)}")
            self.scan_button.setEnabled(True)
            self.import_button.setEnabled(False)
            self.scanned_data = None
            
            # Load and display image preview
            self.display_image_preview(filename)
            self.status_label.setText("Image loaded. Click 'Scan QR Code' to decode.")
    
    def display_image_preview(self, image_path):
        try:
            # Load image and convert to QPixmap
            pil_image = Image.open(image_path)
            
            # Convert to Qt format
            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')
            
            qt_image = ImageQt.ImageQt(pil_image)
            pixmap = QPixmap.fromImage(qt_image)
            
            # Scale to fit preview area
            scaled_pixmap = pixmap.scaled(
                self.image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            
            self.image_label.setPixmap(scaled_pixmap)
            
        except Exception as e:
            self.image_label.setText(f"Failed to load image preview:\n{str(e)}")
            MessageBoxes.show_error(self, "Image Error", f"Failed to load image:\n{str(e)}")
    
    def scan_qr_code(self):
        if not self.current_image_path:
            MessageBoxes.show_error(self, "Error", "No image file selected")
            return
        
        self.scan_button.setEnabled(False)
        self.status_label.setText("Scanning QR code...")
        
        self.scan_worker = QRScanWorker(self.current_image_path)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()
    
    def on_scan_finished(self, success, result):
        self.scan_button.setEnabled(True)
        
        if success:
            self.scanned_data = result
            self.display_scanned_data(result)
            self.import_button.setEnabled(True)
            self.status_label.setText("QR code scanned successfully!")
        else:
            MessageBoxes.show_error(self, "Scan Failed", f"Failed to scan QR code:\n{result}")
            self.status_label.setText("QR code scan failed")
            self.data_display.setPlainText("Scanned QR code data will appear here")
    
    def display_scanned_data(self, qr_data):
        try:
            display_text = f"""Email: {qr_data['email']}
Creation Date: {qr_data['creation_date']}
Public Key: {qr_data['public_key'][:100]}...

Raw QR Data: {qr_data['raw_data'][:150]}..."""
            
            self.data_display.setPlainText(display_text)
            
        except Exception as e:
            self.data_display.setPlainText(f"Error displaying data: {str(e)}")
    
    def import_public_key(self):
        if not self.scanned_data or not self.current_image_path:
            MessageBoxes.show_error(self, "Error", "No QR code data to import")
            return
        
        user = self.session_manager.get_current_user()
        if not user:
            MessageBoxes.show_error(self, "Error", "No user session found")
            return
        
        # Confirm import
        email = self.scanned_data['email']
        creation_date = self.scanned_data['creation_date']
        
        reply = MessageBoxes.show_question(
            self, 
            "Confirm Import", 
            f"Import public key for {email}?\n\nCreation Date: {creation_date}\n\nThis will add the public key to your contact list for encryption purposes."
        )
        
        if reply != MessageBoxes.Yes:
            return
        
        self.import_button.setEnabled(False)
        self.status_label.setText("Importing public key...")
        
        self.import_worker = QRImportWorker(user['user_id'], self.current_image_path)
        self.import_worker.finished.connect(self.on_import_finished)
        self.import_worker.start()
    
    def on_import_finished(self, success, result):
        self.import_button.setEnabled(True)
        
        if success:
            MessageBoxes.show_info(
                self, 
                "Import Successful", 
                f"Successfully imported public key!\n\n{result['message']}"
            )
            self.status_label.setText(f"Public key imported for {result['owner_email']}")
        else:
            MessageBoxes.show_error(self, "Import Failed", f"Failed to import public key:\n{result}")
            self.status_label.setText("Public key import failed")
    
    def closeEvent(self, event):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        if self.import_worker and self.import_worker.isRunning():
            self.import_worker.terminate()
            self.import_worker.wait()
        event.accept() 
