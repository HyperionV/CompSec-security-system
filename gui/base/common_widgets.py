"""
Common Widgets
Reusable GUI components used throughout the application
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QProgressBar, QPushButton, QTextEdit, QFrame,
                             QLineEdit, QGroupBox, QFormLayout, QSpacerItem,
                             QSizePolicy)
from PyQt5.QtCore import QTimer, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QPixmap

class StatusIndicator(QWidget):
    """Widget to show status with color coding"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        self.indicator = QLabel()
        self.indicator.setFixedSize(12, 12)
        self.indicator.setStyleSheet("border-radius: 6px; background-color: gray;")
        
        self.text_label = QLabel("Unknown")
        
        layout.addWidget(self.indicator)
        layout.addWidget(self.text_label)
        layout.addStretch()
        
    def set_status(self, status, text):
        """Set status indicator color and text"""
        colors = {
            'success': '#28a745',
            'valid': '#28a745',
            'warning': '#ffc107',
            'expiring': '#ffc107',
            'error': '#dc3545',
            'expired': '#dc3545',
            'info': '#17a2b8',
            'inactive': '#6c757d'
        }
        
        color = colors.get(status.lower(), '#6c757d')
        self.indicator.setStyleSheet(f"border-radius: 6px; background-color: {color};")
        self.text_label.setText(text)


class ProgressDialog(QWidget):
    """Progress dialog for long-running operations"""
    
    operation_cancelled = pyqtSignal()
    
    def __init__(self, title="Processing...", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(400, 150)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        self.title_label = QLabel("Processing...")
        title_font = QFont()
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        layout.addWidget(self.title_label)
        
        # Status
        self.status_label = QLabel("Please wait...")
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Cancel button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.operation_cancelled.emit)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
    def set_progress(self, value, status=None):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        if status:
            self.status_label.setText(status)
            
    def set_indeterminate(self):
        """Set progress bar to indeterminate mode"""
        self.progress_bar.setRange(0, 0)
        
    def hide_cancel_button(self):
        """Hide the cancel button"""
        self.cancel_button.hide()


class KeyStatusWidget(QWidget):
    """Widget to display key status information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # Key info layout
        info_layout = QFormLayout()
        
        self.email_label = QLabel("Not set")
        self.created_label = QLabel("Not set")
        self.expires_label = QLabel("Not set")
        self.status_indicator = StatusIndicator()
        
        info_layout.addRow("Email:", self.email_label)
        info_layout.addRow("Created:", self.created_label)
        info_layout.addRow("Expires:", self.expires_label)
        info_layout.addRow("Status:", self.status_indicator)
        
        layout.addLayout(info_layout)
        
    def update_key_info(self, email, created_date, expires_date, status):
        """Update key information display"""
        self.email_label.setText(email or "Not set")
        self.created_label.setText(created_date or "Not set")
        self.expires_label.setText(expires_date or "Not set")
        
        # Determine status color and text
        if status == 'valid':
            self.status_indicator.set_status('valid', 'Valid')
        elif status == 'expiring_soon':
            self.status_indicator.set_status('warning', 'Expiring Soon')
        elif status == 'expired':
            self.status_indicator.set_status('error', 'Expired')
        else:
            self.status_indicator.set_status('inactive', 'Unknown')


class FileInfoWidget(QWidget):
    """Widget to display file information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.filename_label = QLabel("No file selected")
        self.size_label = QLabel("-")
        self.format_label = QLabel("-")
        
        layout.addRow("File:", self.filename_label)
        layout.addRow("Size:", self.size_label)
        layout.addRow("Format:", self.format_label)
        
    def update_file_info(self, filename, size_bytes, file_format=None):
        """Update file information display"""
        self.filename_label.setText(filename or "No file selected")
        
        if size_bytes is not None:
            if size_bytes < 1024:
                size_text = f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                size_text = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                size_text = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                size_text = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
            self.size_label.setText(size_text)
        else:
            self.size_label.setText("-")
            
        self.format_label.setText(file_format or "-")


class LogViewWidget(QWidget):
    """Widget for displaying activity logs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.clear_button = QPushButton("Clear View")
        
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addWidget(self.clear_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Courier", 9))
        layout.addWidget(self.log_display)
        
    def add_log_entry(self, timestamp, action, status, details):
        """Add a log entry to the display"""
        status_symbol = "✓" if status == 'success' else "⚠" if status == 'warning' else "✗"
        entry = f"[{timestamp}] {status_symbol} {action}: {details}\n"
        self.log_display.append(entry.strip())
        
    def clear_logs(self):
        """Clear the log display"""
        self.log_display.clear()


class QRCodeDisplayWidget(QWidget):
    """Widget for displaying QR codes"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setAlignment(Qt.AlignCenter)
        
        # QR Code display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet("border: 1px solid #cccccc; background-color: white;")
        self.qr_label.setMinimumSize(250, 250)
        self.qr_label.setText("No QR Code")
        
        layout.addWidget(self.qr_label)
        
        # Info label
        self.info_label = QLabel("QR Code will appear here")
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("color: #666666;")
        
        layout.addWidget(self.info_label)
        
    def display_qr_code(self, qr_pixmap, info_text=""):
        """Display QR code image"""
        if qr_pixmap:
            # Scale pixmap to fit widget
            scaled_pixmap = qr_pixmap.scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_label.setPixmap(scaled_pixmap)
            self.info_label.setText(info_text)
        else:
            self.clear_qr_code()
            
    def clear_qr_code(self):
        """Clear the QR code display"""
        self.qr_label.clear()
        self.qr_label.setText("No QR Code")
        self.info_label.setText("QR Code will appear here") 
