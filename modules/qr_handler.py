import qrcode
import base64
import io
import os
from PIL import Image
from pyzbar import pyzbar
from datetime import datetime
from .logger import security_logger

# Utility functions for safe datetime handling
def safe_to_datetime(dt_value):
    """Convert string or datetime to datetime object safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, datetime):
        return dt_value
    if isinstance(dt_value, str):
        return datetime.fromisoformat(dt_value)
    return datetime.fromisoformat(str(dt_value))

def safe_to_isoformat(dt_value):
    """Convert string or datetime to ISO format string safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, str):
        return dt_value  # Already a string
    if hasattr(dt_value, 'isoformat'):
        return dt_value.isoformat()
    return str(dt_value)  # fallback to string conversion

def safe_to_date_string(dt_value):
    """Convert string or datetime to YYYY-MM-DD date string safely"""
    if dt_value is None:
        return None
    if isinstance(dt_value, str):
        return dt_value[:10]  # Extract date part if it's already a string
    if hasattr(dt_value, 'strftime'):
        return dt_value.strftime('%Y-%m-%d')
    return str(dt_value)[:10]  # fallback

class QRCodeHandler:
    def __init__(self):
        self.qr_codes_dir = "data/qr_codes"
        os.makedirs(self.qr_codes_dir, exist_ok=True)
    
    def generate_qr_code(self, data, filename=None, save_to_file=True):
        """Generate QR code from data"""
        try:
            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # Create image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            img_buffer = io.BytesIO()
            qr_image.save(img_buffer, format='PNG')
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            result = {
                'qr_code_base64': img_base64,
                'data': data
            }
            
            # Save to file if requested
            if save_to_file and filename:
                filepath = os.path.join(self.qr_codes_dir, filename)
                qr_image.save(filepath)
                result['filepath'] = filepath
                
                security_logger.log_activity(
                    action='qr_code_generated',
                    status='success',
                    details=f'QR code saved to {filepath}',
                    email=None  # Generic QR code generation, no user context
                )
            
            return True, result
            
        except Exception as e:
            security_logger.log_activity(
                action='qr_code_generated',
                status='failure',
                details=f'Exception: {str(e)}',
                email=None  # Generic QR code generation, no user context
            )
            return False, str(e)
    
    def read_qr_code(self, image_path):
        """Read QR code from image file"""
        try:
            # Load image
            image = Image.open(image_path)
            
            # Decode QR codes
            qr_codes = pyzbar.decode(image)
            
            if qr_codes:
                # Return data from first QR code found
                qr_data = qr_codes[0].data.decode('utf-8')
                
                security_logger.log_activity(
                    action='qr_code_read',
                    status='success',
                    details=f'QR code read from {image_path}',
                    email=None  # Generic QR code reading, no user context
                )
                
                return True, qr_data
            else:
                security_logger.log_activity(
                    action='qr_code_read',
                    status='failure',
                    details=f'No QR code found in {image_path}',
                    email=None  # Generic QR code reading, no user context
                )
                return False, "No QR code found in image"
                
        except Exception as e:
            security_logger.log_activity(
                action='qr_code_read',
                status='failure',
                details=f'Exception reading {image_path}: {str(e)}',
                email=None  # Generic QR code reading, no user context
            )
            return False, str(e)
    
    def generate_public_key_qr(self, email, public_key, creation_date=None):
        """Generate QR code for public key sharing"""
        try:
            if creation_date is None:
                creation_date = datetime.now().strftime('%Y-%m-%d')
            
            # Format: email|creation_date|public_key_base64
            public_key_base64 = base64.b64encode(public_key.encode()).decode()
            qr_data = f"{email}|{creation_date}|{public_key_base64}"
            
            # Generate filename
            safe_email = email.replace('@', '_').replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"pubkey_{safe_email}_{timestamp}.png"
            
            success, result = self.generate_qr_code(qr_data, filename)
            
            if success:
                result['email'] = email
                result['creation_date'] = creation_date
                result['public_key'] = public_key
                
                security_logger.log_activity(
                    action='public_key_qr_generated',
                    status='success',
                    details=f'Public key QR code generated for {email}',
                    email=email
                )
            
            return success, result
            
        except Exception as e:
            security_logger.log_activity(
                action='public_key_qr_generated',
                status='failure',
                details=f'Exception: {str(e)}',
                email=email if 'email' in locals() else None
            )
            return False, str(e)
    
    def read_public_key_qr(self, image_path):
        """Read and parse public key QR code"""
        try:
            success, qr_data = self.read_qr_code(image_path)
            
            if not success:
                return False, qr_data
            
            # Parse QR data: email|creation_date|public_key_base64
            parts = qr_data.split('|')
            if len(parts) != 3:
                return False, "Invalid QR code format"
            
            email, creation_date, public_key_base64 = parts
            
            # Decode public key
            try:
                public_key = base64.b64decode(public_key_base64).decode()
            except Exception:
                return False, "Invalid public key encoding"
            
            result = {
                'email': email,
                'creation_date': creation_date,
                'public_key': public_key,
                'raw_data': qr_data
            }
            
            security_logger.log_activity(
                action='public_key_qr_read',
                status='success',
                details=f'Public key QR code read for {email}',
                email=email
            )
            
            return True, result
            
        except Exception as e:
            security_logger.log_activity(
                action='public_key_qr_read',
                status='failure',
                details=f'Exception: {str(e)}',
                email=None  # No user context available in exception
            )
            return False, str(e)
    
    def list_qr_codes(self):
        """List all QR code files in the directory"""
        try:
            files = []
            for filename in os.listdir(self.qr_codes_dir):
                if filename.lower().endswith('.png'):
                    filepath = os.path.join(self.qr_codes_dir, filename)
                    file_info = {
                        'filename': filename,
                        'filepath': filepath,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
                    }
                    files.append(file_info)
            
            return True, sorted(files, key=lambda x: x['modified'], reverse=True)
            
        except Exception as e:
            return False, str(e)

    def generate_user_public_key_qr(self, user_id, email):
        """Generate QR code for user's own public key"""
        from .key_manager import key_manager
        from .database import db
        
        try:
            # Get user's current public key
            success, message, key_data = key_manager.get_user_keys(user_id)
            if not success or not key_data:
                return False, "No valid keys found for user"
            
            public_key_pem = key_data['public_key']
            creation_date = safe_to_date_string(key_data['created_at'])  # Safe conversion
            
            # Generate QR code
            success, result = self.generate_public_key_qr(email, public_key_pem, creation_date)
            
            if success:
                security_logger.log_activity(
                    user_id=user_id,
                    action='public_key_qr_generated',
                    status='success',
                    details=f'Generated QR code for own public key',
                    email=email
                )
            
            return success, result
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='public_key_qr_generated',
                status='failure',
                details=f'Failed to generate QR code: {str(e)}',
                email=email
            )
            return False, str(e)
    
    def import_public_key_from_qr(self, user_id, image_path):
        """Import public key from QR code and store in database"""
        from .database import db
        
        try:
            # Get user email for logging
            user_email = db.get_user_email_by_id(user_id)
            
            # Read QR code
            success, qr_result = self.read_public_key_qr(image_path)
            if not success:
                return False, qr_result
            
            # Extract data
            owner_email = qr_result['email']
            public_key = qr_result['public_key']
            creation_date = qr_result['creation_date']
            
            # Import into database
            key_id = db.import_public_key(owner_email, public_key, creation_date, user_id)
            
            if key_id:
                security_logger.log_activity(
                    user_id=user_id,
                    action='public_key_imported',
                    status='success',
                    details=f'Imported public key for {owner_email} from QR code',
                    email=user_email
                )
                
                result = {
                    'key_id': key_id,
                    'owner_email': owner_email,
                    'creation_date': creation_date,
                    'message': f'Successfully imported public key for {owner_email}'
                }
                return True, result
            else:
                return False, "Failed to store public key in database"
            
        except Exception as e:
            # Try to get user email even in exception case
            try:
                user_email = db.get_user_email_by_id(user_id)
            except:
                user_email = None
                
            security_logger.log_activity(
                user_id=user_id,
                action='public_key_imported',
                status='failure',
                details=f'Failed to import public key: {str(e)}',
                email=user_email
            )
            return False, str(e)

qr_handler = QRCodeHandler() 