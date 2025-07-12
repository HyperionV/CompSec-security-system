import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QWidget
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Application")
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(800, 600)
        
        # Set application font
        font = QFont("Arial", 10)
        self.setFont(font)
        
        # Create central stacked widget for screen navigation
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Screen indices
        self.LOGIN_SCREEN = 0
        self.MFA_SCREEN = 1
        self.MAIN_APP_SCREEN = 2
        
        # Initialize screens (will be set by application)
        self.login_screen = None
        self.mfa_screen = None
        self.main_app_screen = None
    
    def add_login_screen(self, screen):
        """Add login screen to stack"""
        self.login_screen = screen
        self.stacked_widget.addWidget(screen)
    
    def add_mfa_screen(self, screen):
        """Add MFA screen to stack"""
        # Remove old MFA screen if it exists
        if self.mfa_screen and self.stacked_widget.indexOf(self.mfa_screen) != -1:
            self.stacked_widget.removeWidget(self.mfa_screen)
            self.mfa_screen.deleteLater()
        
        self.mfa_screen = screen
        self.stacked_widget.addWidget(screen)
    
    def add_main_app_screen(self, screen):
        """Add main application screen to stack"""
        # Remove old main app screen if it exists
        if self.main_app_screen and self.stacked_widget.indexOf(self.main_app_screen) != -1:
            self.stacked_widget.removeWidget(self.main_app_screen)
            self.main_app_screen.deleteLater()
        
        self.main_app_screen = screen
        self.stacked_widget.addWidget(screen)
    
    def show_login_screen(self):
        """Show login/register screen"""
        # Clear login form when returning to login
        if self.login_screen and hasattr(self.login_screen, 'reset_for_new_session'):
            self.login_screen.reset_for_new_session()
        self.stacked_widget.setCurrentIndex(self.LOGIN_SCREEN)
    
    def show_mfa_screen(self):
        """Show MFA verification screen"""
        self.stacked_widget.setCurrentIndex(self.MFA_SCREEN)
    
    def show_main_app_screen(self):
        """Show main application screen"""
        self.stacked_widget.setCurrentIndex(self.MAIN_APP_SCREEN)
    
    def cleanup_screens(self):
        """Clean up all screens when switching users"""
        # Remove MFA screen
        if self.mfa_screen and self.stacked_widget.indexOf(self.mfa_screen) != -1:
            self.stacked_widget.removeWidget(self.mfa_screen)
            self.mfa_screen.deleteLater()
            self.mfa_screen = None
        
        # Remove main app screen
        if self.main_app_screen and self.stacked_widget.indexOf(self.main_app_screen) != -1:
            self.stacked_widget.removeWidget(self.main_app_screen)
            self.main_app_screen.deleteLater()
            self.main_app_screen = None
    
    def closeEvent(self, event):
        """Handle application close"""
        event.accept() 