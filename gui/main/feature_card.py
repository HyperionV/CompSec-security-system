from PyQt5.QtWidgets import QFrame, QVBoxLayout, QLabel, QSizePolicy
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont, QCursor

class FeatureCard(QFrame):
    clicked = pyqtSignal(str)
    
    def __init__(self, feature_id, title, description, parent=None):
        super().__init__(parent)
        self.feature_id = feature_id
        self.title = title
        self.description = description
        self.setupUI()
        
    def setupUI(self):
        self.setFrameStyle(QFrame.Box)
        self.setLineWidth(1)
        self.setFixedSize(220, 120)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)
        
        title_label = QLabel(self.title)
        title_font = QFont()
        title_font.setPointSize(10)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        
        desc_label = QLabel(self.description)
        desc_font = QFont()
        desc_font.setPointSize(8)
        desc_label.setFont(desc_font)
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #666666;")
        
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        
        self.setLayout(layout)
        self.setStyleSheet("""
            FeatureCard {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
            FeatureCard:hover {
                background-color: #e9ecef;
                border: 1px solid #adb5bd;
            }
        """)
        
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.feature_id)
        super().mousePressEvent(event) 
