from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QLineEdit, QLabel, QFormLayout, QHeaderView)
from PyQt5.QtCore import Qt
from ..utils.dialogs import show_error, show_info, show_warning, get_open_file, get_save_file

class QROperationsTab(QWidget):
    def __init__(self, user_session, managers, parent=None):
        super().__init__(parent)
        self.user_session = user_session
        self.managers = managers
        self.qr_handler = managers['qr_handler']
        self.db = managers['db']
        self.setup_ui()
        self.refresh_data()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # QR Code Generation Section
        gen_group = QGroupBox("Generate QR Code")
        gen_layout = QVBoxLayout()
        
        gen_info = QLabel("Generate a QR code containing your public key for easy sharing.")
        gen_layout.addWidget(gen_info)
        
        self.generate_button = QPushButton("Generate QR Code for My Public Key")
        self.generate_button.clicked.connect(self.generate_qr_code)
        gen_layout.addWidget(self.generate_button)
        
        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)
        
        # QR Code Import Section
        import_group = QGroupBox("Import Public Key from QR Code")
        import_layout = QVBoxLayout()
        
        import_info = QLabel("Import someone else's public key by scanning their QR code image.")
        import_layout.addWidget(import_info)
        
        self.import_button = QPushButton("Import Public Key from QR Code")
        self.import_button.clicked.connect(self.import_qr_code)
        import_layout.addWidget(self.import_button)
        
        import_group.setLayout(import_layout)
        layout.addWidget(import_group)
        
        # Search Section
        search_group = QGroupBox("Search Public Keys")
        search_layout = QFormLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter email to search")
        self.search_input.returnPressed.connect(self.search_keys)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_keys)
        
        search_row_layout = QHBoxLayout()
        search_row_layout.addWidget(self.search_input)
        search_row_layout.addWidget(search_button)
        
        search_layout.addRow("Email:", search_row_layout)
        search_group.setLayout(search_layout)
        layout.addWidget(search_group)
        
        # Imported Keys Table
        table_group = QGroupBox("Imported Public Keys")
        table_layout = QVBoxLayout()
        
        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(4)
        self.keys_table.setHorizontalHeaderLabels([
            "Owner Email", "Creation Date", "Import Date", "Status"
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
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_data)
        table_buttons.addWidget(self.refresh_button)
        
        table_buttons.addStretch()
        table_layout.addLayout(table_buttons)
        
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
        
        self.setLayout(layout)
    
    def generate_qr_code(self):
        """Generate QR code for user's public key"""
        try:
            user_email = self.user_session.user_info['email']
            
            # Check if user has valid keys
            user_keys = self.db.get_user_keys_by_id(self.user_session.user_info['id'])
            if not user_keys:
                show_warning(self, "No Keys Found", 
                           "You don't have any RSA keys. Please generate keys first in the Key Management tab.")
                return
            
            # Get save location
            save_path = get_save_file(self, "Save QR Code", "PNG Images (*.png)")
            if not save_path:
                return
            
            if not save_path.lower().endswith('.png'):
                save_path += '.png'
            
            # Generate QR code
            success, result = self.qr_handler.generate_user_public_key_qr(
                self.user_session.user_info['id'], user_email
            )
            
            if success:
                # Save to specified location
                import shutil
                if 'filepath' in result:
                    shutil.move(result['filepath'], save_path)
                message = f"QR code saved successfully to: {save_path}"
            else:
                message = result
            
            if success:
                show_info(self, "QR Code Generated", 
                         f"QR code saved successfully to:\n{save_path}")
            else:
                show_error(self, "Generation Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to generate QR code: {str(e)}")
    
    def import_qr_code(self):
        """Import public key from QR code image"""
        try:
            # Get QR code file
            qr_file = get_open_file(self, "Select QR Code Image", 
                                   "Image Files (*.png *.jpg *.jpeg *.bmp)")
            if not qr_file:
                return
            
            # Import the QR code
            success, result = self.qr_handler.import_public_key_from_qr(
                self.user_session.user_info['id'], qr_file
            )
            
            if success:
                message = result.get('message', 'Public key imported successfully')
            else:
                message = result
            
            if success:
                show_info(self, "Import Successful", message)
                self.refresh_data()
            else:
                show_error(self, "Import Failed", message)
                
        except Exception as e:
            show_error(self, "Error", f"Failed to import QR code: {str(e)}")
    
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
            
            if results:
                # Clear table and show results
                self.keys_table.setRowCount(0)
                for result in results:
                    self.add_key_to_table(result)
                show_info(self, "Search Results", f"Found {len(results)} matching keys.")
            else:
                show_info(self, "Search Results", "No keys found matching that email.")
                
        except Exception as e:
            show_error(self, "Search Error", f"Failed to search keys: {str(e)}")
    
    def refresh_data(self):
        """Refresh the imported keys table"""
        try:
            # Get all imported public keys
            keys = self.db.get_public_keys_by_user(self.user_session.user_info['id'])
            
            # Clear and populate table
            self.keys_table.setRowCount(0)
            for key in keys:
                self.add_key_to_table(key)
                
        except Exception as e:
            show_error(self, "Refresh Error", f"Failed to refresh data: {str(e)}")
    
    def add_key_to_table(self, key_data):
        """Add a key to the table"""
        row = self.keys_table.rowCount()
        self.keys_table.insertRow(row)
        
        # Owner Email
        self.keys_table.setItem(row, 0, QTableWidgetItem(key_data['owner_email']))
        
        # Creation Date
        self.keys_table.setItem(row, 1, QTableWidgetItem(key_data['creation_date']))
        
        # Import Date
        import_date = key_data['imported_at'].split('T')[0] if 'T' in key_data['imported_at'] else key_data['imported_at']
        self.keys_table.setItem(row, 2, QTableWidgetItem(import_date))
        
        # Status
        status = "Active" if key_data['is_active'] else "Inactive"
        self.keys_table.setItem(row, 3, QTableWidgetItem(status)) 