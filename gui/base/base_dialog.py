"""
Base Dialog Class
Provides common functionality for all application dialogs
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QFrame, QDialogButtonBox)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont

from ..app import session_manager
from modules.logger import security_logger

class BaseDialog(QDialog):
    """Base class for all application dialogs"""
    
    # Signals for dialog events
    dialog_accepted = pyqtSignal()
    dialog_rejected = pyqtSignal()
    
    def __init__(self, title="Dialog", parent=None, modal=True):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(modal)
        self.setMinimumWidth(400)
        
        # Setup dialog
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup the basic dialog UI structure"""
        # Create main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(10)
        
        # Create content area
        self.content_widget = QFrame()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(10)
        
        # Add content widget to main layout
        self.main_layout.addWidget(self.content_widget)
        
        # Create button box
        self.button_box = QDialogButtonBox()
        self.main_layout.addWidget(self.button_box)
        
    def connect_signals(self):
        """Connect signals"""
        if hasattr(self, 'button_box') and self.button_box:
            self.button_box.accepted.connect(self.accept)
            self.button_box.rejected.connect(self.reject)
        
    def add_standard_buttons(self, buttons=QDialogButtonBox.Ok | QDialogButtonBox.Cancel):
        """Add standard buttons to the dialog"""
        self.button_box.setStandardButtons(buttons)
        
    def add_custom_button(self, text, role=QDialogButtonBox.ActionRole):
        """Add a custom button to the dialog"""
        button = self.button_box.addButton(text, role)
        return button
        
    def set_ok_button_text(self, text):
        """Set custom text for OK button"""
        ok_button = self.button_box.button(QDialogButtonBox.Ok)
        if ok_button:
            ok_button.setText(text)
            
    def set_cancel_button_text(self, text):
        """Set custom text for Cancel button"""
        cancel_button = self.button_box.button(QDialogButtonBox.Cancel)
        if cancel_button:
            cancel_button.setText(text)
            
    def add_title_label(self, title, subtitle=None):
        """Add a title label to the dialog"""
        title_label = QLabel(title)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        self.content_layout.addWidget(title_label)
        
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setWordWrap(True)
            subtitle_label.setStyleSheet("color: #666666;")
            self.content_layout.addWidget(subtitle_label)
            
        # Add separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        self.content_layout.addWidget(separator)
        
    def add_content_widget(self, widget):
        """Add a widget to the content area"""
        self.content_layout.addWidget(widget)
        
    def add_content_layout(self, layout):
        """Add a layout to the content area"""
        self.content_layout.addLayout(layout)
        
    def log_action(self, action, status='success', details=None):
        """Log user action"""
        user_id = session_manager.get_user_id()
        security_logger.log_activity(
            user_id=user_id,
            action=action,
            status=status,
            details=details
        )
        
    def accept(self):
        """Handle dialog acceptance"""
        self.dialog_accepted.emit()
        super().accept()
        
    def reject(self):
        """Handle dialog rejection"""
        self.dialog_rejected.emit()
        super().reject()


class ConfirmationDialog(BaseDialog):
    """Standard confirmation dialog"""
    
    def __init__(self, title, message, parent=None):
        super().__init__(title, parent)
        self.setup_confirmation_ui(message)
        
    def setup_confirmation_ui(self, message):
        """Setup confirmation dialog UI"""
        # Add message
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        self.add_content_widget(message_label)
        
        # Add standard buttons
        self.add_standard_buttons(QDialogButtonBox.Yes | QDialogButtonBox.No)
        
        # Set button texts
        yes_button = self.button_box.button(QDialogButtonBox.Yes)
        no_button = self.button_box.button(QDialogButtonBox.No)
        
        if yes_button:
            yes_button.setText("Yes")
        if no_button:
            no_button.setText("No") 
