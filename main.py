#!/usr/bin/env python3

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from gui.login_window import LoginWindow
from modules.logger import security_logger

def main():
    security_logger.log_system_startup("SecurityApp v1.0.0 starting")
    
    app = QApplication(sys.argv)
    app.setApplicationName("SecurityApp")
    app.setApplicationVersion("1.0.0")
    
    login_window = LoginWindow()
    login_window.show()
    
    result = app.exec_()
    
    security_logger.log_system_shutdown("SecurityApp shutting down")
    sys.exit(result)

if __name__ == "__main__":
    main() 