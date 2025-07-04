from PyQt5.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from datetime import datetime

class UserStatusWidget(QWidget):
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.setupUI()
        self.updateStatus()
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateTime)
        self.timer.start(1000)
        
    def setupUI(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(20)
        
        user_info_frame = self.createUserInfoSection()
        session_info_frame = self.createSessionInfoSection()
        time_frame = self.createTimeSection()
        
        layout.addWidget(user_info_frame)
        layout.addWidget(session_info_frame)
        layout.addStretch()
        layout.addWidget(time_frame)
        
        self.setLayout(layout)
        self.setStyleSheet("""
            UserStatusWidget {
                background-color: #2c3e50;
                border-bottom: 2px solid #34495e;
            }
            QLabel {
                color: white;
            }
        """)
        
    def createUserInfoSection(self):
        frame = QFrame()
        layout = QVBoxLayout()
        layout.setSpacing(2)
        
        self.user_name_label = QLabel("User Name")
        self.user_name_label.setFont(self.getBoldFont(11))
        
        self.user_email_label = QLabel("user@example.com")
        self.user_email_label.setFont(self.getRegularFont(9))
        self.user_email_label.setStyleSheet("color: #bdc3c7;")
        
        layout.addWidget(self.user_name_label)
        layout.addWidget(self.user_email_label)
        frame.setLayout(layout)
        return frame
        
    def createSessionInfoSection(self):
        frame = QFrame()
        layout = QVBoxLayout()
        layout.setSpacing(2)
        
        session_label = QLabel("Session Status")
        session_label.setFont(self.getBoldFont(10))
        
        self.session_status_label = QLabel("Active")
        self.session_status_label.setFont(self.getRegularFont(9))
        self.session_status_label.setStyleSheet("color: #2ecc71;")
        
        layout.addWidget(session_label)
        layout.addWidget(self.session_status_label)
        frame.setLayout(layout)
        return frame
        
    def createTimeSection(self):
        frame = QFrame()
        layout = QVBoxLayout()
        layout.setSpacing(2)
        
        time_label = QLabel("Current Time")
        time_label.setFont(self.getBoldFont(10))
        
        self.current_time_label = QLabel("")
        self.current_time_label.setFont(self.getRegularFont(9))
        self.current_time_label.setStyleSheet("color: #bdc3c7;")
        
        layout.addWidget(time_label)
        layout.addWidget(self.current_time_label)
        frame.setLayout(layout)
        return frame
        
    def getBoldFont(self, size):
        font = QFont()
        font.setPointSize(size)
        font.setBold(True)
        return font
        
    def getRegularFont(self, size):
        font = QFont()
        font.setPointSize(size)
        return font
        
    def updateStatus(self):
        if self.session_manager and hasattr(self.session_manager, 'current_user'):
            user = self.session_manager.current_user
            if user:
                self.user_name_label.setText(f"{user.get('name', 'Unknown User')}")
                self.user_email_label.setText(user.get('email', 'No email'))
            else:
                self.user_name_label.setText("Guest User")
                self.user_email_label.setText("Not authenticated")
                
    def updateTime(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.current_time_label.setText(current_time) 
