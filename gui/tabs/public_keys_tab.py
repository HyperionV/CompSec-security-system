from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QLabel, QLineEdit, QFormLayout,
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt
from ..utils.dialogs import show_error, show_info, show_warning, QRCodeDialog
from datetime import datetime, timedelta

class PublicKeysTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.db = managers['db']
        self.public_key_manager = managers.get('public_key_manager')
        self.setup_ui()
        self.refresh_data()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Search Section
        search_group = QGroupBox("Search Public Keys")
        search_layout = QFormLayout()
        
        search_row_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter email to search for public keys")
        self.search_input.returnPressed.connect(self.search_keys)
        search_row_layout.addWidget(self.search_input)
        
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_keys)
        search_row_layout.addWidget(self.search_button)
        
        search_layout.addRow("Email:", search_row_layout)
        search_group.setLayout(search_layout)
        layout.addWidget(search_group)
        
        # Public Keys Table
        table_group = QGroupBox("Available Public Keys")
        table_layout = QVBoxLayout()
        
        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(4)
        self.keys_table.setHorizontalHeaderLabels([
            "Email", "QR Code", "Creation Date", "Expire In"
        ])
        
        # Set column resize mode
        header = self.keys_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        table_layout.addWidget(self.keys_table)
        
        # Table control buttons
        table_buttons = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh All Keys")
        self.refresh_button.clicked.connect(self.refresh_data)
        table_buttons.addWidget(self.refresh_button)
        
        self.show_all_button = QPushButton("Show All Keys")
        self.show_all_button.clicked.connect(self.show_all_keys)
        table_buttons.addWidget(self.show_all_button)
        
        table_buttons.addStretch()
        table_layout.addLayout(table_buttons)
        
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
       
        layout.addStretch()
        self.setLayout(layout)
    
    def search_keys(self):
        """Search for public keys by email"""
        search_email = self.search_input.text().strip()
        if not search_email:
            show_warning(self, "Search Error", "Please enter an email to search.")
            return
        
        try:
            # Search in imported keys
            results = self.db.search_public_key_by_email(
                self.user_session.user_info['id'], search_email
            )
            
            # Clear table and show results
            self.keys_table.setRowCount(0)
            
            if results:
                for result in results:
                    self.add_key_to_table(result)
                show_info(self, "Search Results", f"Found {len(results)} matching keys.")
            else:
                show_info(self, "Search Results", "No keys found matching that email.")
                
        except Exception as e:
            show_error(self, "Search Error", f"Failed to search keys: {str(e)}")
    
    def show_all_keys(self):
        """Show all imported public keys"""
        self.search_input.clear()
        self.refresh_data()
    
    def refresh_data(self):
        """Refresh the public keys table"""
        try:
            # Get all imported public keys
            keys = self.db.get_public_keys_by_user(self.user_session.user_info['id'])
            
            # Clear and populate table
            self.keys_table.setRowCount(0)
            for key in keys:
                self.add_key_to_table(key)
            
            if not keys:
                # Add a row to show no keys available
                self.keys_table.insertRow(0)
                no_keys_item = QTableWidgetItem("No public keys imported yet")
                no_keys_item.setFlags(Qt.ItemIsSelectable)
                self.keys_table.setItem(0, 0, no_keys_item)
                
                for col in range(1, 4):
                    empty_item = QTableWidgetItem("")
                    empty_item.setFlags(Qt.ItemIsSelectable)
                    self.keys_table.setItem(0, col, empty_item)
                
        except Exception as e:
            show_error(self, "Refresh Error", f"Failed to refresh data: {str(e)}")
    
    def add_key_to_table(self, key_data):
        """Add a key to the table"""
        row = self.keys_table.rowCount()
        self.keys_table.insertRow(row)
        
        # Email
        self.keys_table.setItem(row, 0, QTableWidgetItem(key_data['owner_email']))
        
        # QR Code Button
        qr_button = QPushButton("Show QR")
        qr_button.clicked.connect(lambda: self.show_qr_code(key_data))
        self.keys_table.setCellWidget(row, 1, qr_button)
        
        # Creation Date
        self.keys_table.setItem(row, 2, QTableWidgetItem(key_data['creation_date']))
        
        # Expire In (calculate based on creation_date + 90 days)
        try:
            creation_date = datetime.strptime(key_data['creation_date'], '%Y-%m-%d')
            expiration_date = creation_date + timedelta(days=90)
            days_remaining = (expiration_date - datetime.now()).days
            
            if days_remaining < 0:
                expire_text = f"Expired {abs(days_remaining)} days ago"
            elif days_remaining == 0:
                expire_text = "Expires today"
            else:
                expire_text = f"{days_remaining} days"
        except:
            expire_text = "N/A"
        
        self.keys_table.setItem(row, 3, QTableWidgetItem(expire_text))
    
    def show_qr_code(self, key_data):
        """Show QR code for the selected public key"""
        try:
            dialog = QRCodeDialog(
                key_data['owner_email'],
                key_data['public_key'],
                key_data['creation_date'],
                self
            )
            dialog.exec_()
        except Exception as e:
            show_error(self, "QR Code Error", f"Failed to generate QR code: {str(e)}") 