from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette

class KeyStatusWidget(QWidget):
    def __init__(self, status='unknown', days_remaining=0, parent=None):
        super().__init__(parent)
        self.status = status
        self.days_remaining = days_remaining
        self.setup_ui()
    
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(5)
        
        # Status icon label
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(16, 16)
        self.icon_label.setAlignment(Qt.AlignCenter)
        
        # Status text label  
        self.text_label = QLabel()
        font = QFont()
        font.setPointSize(9)
        font.setBold(True)
        self.text_label.setFont(font)
        
        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addStretch()
        
        self.update_status(self.status, self.days_remaining)
    
    def update_status(self, status, days_remaining=0):
        self.status = status
        self.days_remaining = days_remaining
        
        if status == 'valid':
            self.icon_label.setText('✓')
            self.icon_label.setStyleSheet('color: #28a745; font-weight: bold; font-size: 12px;')
            self.text_label.setText('Valid')
            self.text_label.setStyleSheet('color: #28a745;')
            tooltip = f"Key is valid for {days_remaining} more days"
            
        elif status == 'expiring_soon':
            self.icon_label.setText('⚠')
            self.icon_label.setStyleSheet('color: #ffc107; font-weight: bold; font-size: 12px;')
            self.text_label.setText('Expiring Soon')
            self.text_label.setStyleSheet('color: #ffc107;')
            tooltip = f"Key expires in {days_remaining} days - renewal recommended"
            
        elif status == 'expired':
            self.icon_label.setText('✗')
            self.icon_label.setStyleSheet('color: #dc3545; font-weight: bold; font-size: 12px;')
            self.text_label.setText('Expired')
            self.text_label.setStyleSheet('color: #dc3545;')
            overdue_days = abs(days_remaining)
            tooltip = f"Key expired {overdue_days} days ago - immediate renewal required"
            
        else:
            self.icon_label.setText('?')
            self.icon_label.setStyleSheet('color: #6c757d; font-weight: bold; font-size: 12px;')
            self.text_label.setText('Unknown')
            self.text_label.setStyleSheet('color: #6c757d;')
            tooltip = "Key status unknown"
        
        self.setToolTip(tooltip)
        self.icon_label.setToolTip(tooltip)
        self.text_label.setToolTip(tooltip)
    
    def get_status_info(self):
        return {
            'status': self.status,
            'days_remaining': self.days_remaining,
            'display_text': self.text_label.text(),
            'tooltip': self.toolTip()
        } 
