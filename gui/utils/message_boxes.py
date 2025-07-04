"""
Message Box Utilities
Standardized message boxes and dialogs for the application
"""

from PyQt5.QtWidgets import QMessageBox, QInputDialog, QLineEdit
from PyQt5.QtCore import Qt

class MessageBoxes:
    """Standardized message boxes for the application"""
    
    @staticmethod
    def show_info(parent, title, message, details=None):
        """Show information message box"""
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        if details:
            msg.setDetailedText(details)
        msg.setStandardButtons(QMessageBox.Ok)
        return msg.exec_()
    
    @staticmethod
    def show_warning(parent, title, message, details=None):
        """Show warning message box"""
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle(title)
        msg.setText(message)
        if details:
            msg.setDetailedText(details)
        msg.setStandardButtons(QMessageBox.Ok)
        return msg.exec_()
    
    @staticmethod
    def show_error(parent, title, message, details=None):
        """Show error message box"""
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        if details:
            msg.setDetailedText(details)
        msg.setStandardButtons(QMessageBox.Ok)
        return msg.exec_()
    
    @staticmethod
    def show_question(parent, title, message, default_yes=True):
        """Show yes/no question dialog"""
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Question)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        
        if default_yes:
            msg.setDefaultButton(QMessageBox.Yes)
        else:
            msg.setDefaultButton(QMessageBox.No)
            
        result = msg.exec_()
        return result == QMessageBox.Yes
    
    @staticmethod
    def show_confirmation(parent, title, message, ok_text="OK", cancel_text="Cancel"):
        """Show confirmation dialog with custom button text"""
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Question)
        msg.setWindowTitle(title)
        msg.setText(message)
        
        ok_button = msg.addButton(ok_text, QMessageBox.AcceptRole)
        cancel_button = msg.addButton(cancel_text, QMessageBox.RejectRole)
        msg.setDefaultButton(ok_button)
        
        result = msg.exec_()
        return msg.clickedButton() == ok_button
    
    @staticmethod
    def get_password(parent, title, prompt, echo_mode=QLineEdit.Password):
        """Get password input from user"""
        text, ok = QInputDialog.getText(
            parent, title, prompt, echo_mode
        )
        return text if ok else None
    
    @staticmethod
    def get_text_input(parent, title, prompt, default_text=""):
        """Get text input from user"""
        text, ok = QInputDialog.getText(
            parent, title, prompt, QLineEdit.Normal, default_text
        )
        return text if ok else None
    
    @staticmethod
    def show_success(parent, title, message):
        """Show success message with appropriate styling"""
        return MessageBoxes.show_info(parent, title, f"✓ {message}")
    
    @staticmethod
    def show_operation_result(parent, success, operation, message, details=None):
        """Show operation result with appropriate icon and text"""
        if success:
            title = f"{operation} Successful"
            return MessageBoxes.show_success(parent, title, message)
        else:
            title = f"{operation} Failed"
            return MessageBoxes.show_error(parent, title, message, details) 
