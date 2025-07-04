from .base_controller import BaseController
from ..utils.message_boxes import MessageBoxes

class QRCodeController(BaseController):
    def __init__(self, session_manager, parent=None):
        super().__init__(session_manager, parent)
    
    def show_qr_management(self):
        """Show the main QR code management window"""
        try:
            if not self.session_manager.is_authenticated():
                MessageBoxes.show_error(
                    self.parent, 
                    "Authentication Required", 
                    "Please log in to access QR code management"
                )
                return
            
            from ..qr_code.qr_management_window import QRManagementWindow
            window = QRManagementWindow(self.session_manager, self.parent)
            window.show()
            
        except Exception as e:
            MessageBoxes.show_error(
                self.parent, 
                "Error", 
                f"Failed to open QR code management:\n{str(e)}"
            )
    
    def show_qr_generation(self):
        """Show QR code generation dialog"""
        try:
            if not self.session_manager.is_authenticated():
                MessageBoxes.show_error(
                    self.parent, 
                    "Authentication Required", 
                    "Please log in to generate QR codes"
                )
                return
            
            from ..qr_code.qr_generation_dialog import QRGenerationDialog
            dialog = QRGenerationDialog(self.session_manager, self.parent)
            dialog.exec_()
            
        except Exception as e:
            MessageBoxes.show_error(
                self.parent, 
                "Error", 
                f"Failed to open QR code generation:\n{str(e)}"
            )
    
    def show_qr_scan(self):
        """Show QR code scanning dialog"""
        try:
            if not self.session_manager.is_authenticated():
                MessageBoxes.show_error(
                    self.parent, 
                    "Authentication Required", 
                    "Please log in to scan QR codes"
                )
                return
            
            from ..qr_code.qr_scan_dialog import QRScanDialog
            dialog = QRScanDialog(self.session_manager, self.parent)
            dialog.exec_()
            
        except Exception as e:
            MessageBoxes.show_error(
                self.parent, 
                "Error", 
                f"Failed to open QR code scanning:\n{str(e)}"
            )
    
    def generate_user_qr_code(self, user_id, user_email):
        """Generate QR code for user's public key"""
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.generate_user_public_key_qr(user_id, user_email)
            
            if success:
                return True, {
                    'message': 'QR code generated successfully',
                    'qr_data': result
                }
            else:
                return False, f"Failed to generate QR code: {result}"
                
        except Exception as e:
            return False, f"Error generating QR code: {str(e)}"
    
    def scan_qr_code_file(self, image_path):
        """Scan QR code from image file"""
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.read_public_key_qr(image_path)
            
            if success:
                return True, {
                    'message': 'QR code scanned successfully',
                    'qr_data': result
                }
            else:
                return False, f"Failed to scan QR code: {result}"
                
        except Exception as e:
            return False, f"Error scanning QR code: {str(e)}"
    
    def import_public_key_from_qr(self, user_id, image_path):
        """Import public key from QR code and store in database"""
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.import_public_key_from_qr(user_id, image_path)
            
            if success:
                return True, {
                    'message': f"Successfully imported public key for {result['owner_email']}",
                    'import_data': result
                }
            else:
                return False, f"Failed to import public key: {result}"
                
        except Exception as e:
            return False, f"Error importing public key: {str(e)}"
    
    def list_qr_codes(self):
        """List all QR code files"""
        try:
            from modules.qr_handler import qr_handler
            success, result = qr_handler.list_qr_codes()
            
            if success:
                return True, {
                    'message': f'Found {len(result)} QR code files',
                    'files': result
                }
            else:
                return False, f"Failed to list QR codes: {result}"
                
        except Exception as e:
            return False, f"Error listing QR codes: {str(e)}"
    
    def validate_qr_image_file(self, image_path):
        """Validate that file is a supported image format"""
        try:
            import os
            from PIL import Image
            
            # Check file exists
            if not os.path.exists(image_path):
                return False, "File does not exist"
            
            # Check file extension
            supported_formats = ['.png', '.jpg', '.jpeg', '.bmp', '.gif']
            file_ext = os.path.splitext(image_path)[1].lower()
            
            if file_ext not in supported_formats:
                return False, f"Unsupported file format: {file_ext}"
            
            # Try to open with PIL
            try:
                with Image.open(image_path) as img:
                    img.verify()
                return True, "Valid image file"
            except Exception:
                return False, "Invalid or corrupted image file"
                
        except Exception as e:
            return False, f"Error validating image: {str(e)}"
    
    def get_qr_statistics(self):
        """Get statistics about QR code usage"""
        try:
            # Get QR code files count
            success, file_result = self.list_qr_codes()
            qr_files_count = len(file_result['files']) if success else 0
            
            # Get imported public keys count (from QR codes)
            user = self.session_manager.get_current_user()
            if not user:
                return False, "No user session"
            
            from modules.public_key_manager import PublicKeyManager
            from modules.database import db
            from modules.logger import security_logger
            
            pub_key_manager = PublicKeyManager(user['email'], db, security_logger)
            success, all_keys = pub_key_manager.get_all_available_keys()
            
            imported_keys_count = 0
            if success:
                imported_keys_count = len([k for k in all_keys if k['source'] == 'imported'])
            
            return True, {
                'qr_files_generated': qr_files_count,
                'public_keys_imported': imported_keys_count,
                'message': f'QR codes generated: {qr_files_count}, Public keys imported: {imported_keys_count}'
            }
            
        except Exception as e:
            return False, f"Error getting QR statistics: {str(e)}" 
