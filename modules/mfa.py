import pyotp
import qrcode
import io
import base64
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from .database import db
from .logger import security_logger

class MFAManager:
    def __init__(self):
        self.otp_length = 6
        self.otp_expiry_minutes = 5
        # SMTP Configuration (Optional - set to None for simulation mode)
        self.smtp_enabled = False  # Set to True to enable real SMTP
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.smtp_username = ""  # Your email
        self.smtp_password = ""  # Your app password
        self.from_email = "noreply@securityapp.com"
        
    def configure_smtp(self, server, port, username, password, from_email=None):
        """Configure SMTP settings for real email sending"""
        self.smtp_server = server
        self.smtp_port = port
        self.smtp_username = username
        self.smtp_password = password
        self.from_email = from_email or username
        self.smtp_enabled = True
        
        security_logger.log_activity(
            action='smtp_configured',
            status='success',
            details=f'SMTP configured for {server}:{port}'
        )
    
    def send_otp_email(self, user_email, otp_code, expires_at):
        """Send OTP via email (real SMTP or simulation)"""
        if self.smtp_enabled and self.smtp_username and self.smtp_password:
            return self._send_real_email(user_email, otp_code, expires_at)
        else:
            return self._simulate_email(user_email, otp_code, expires_at)
    
    def _send_real_email(self, user_email, otp_code, expires_at):
        """Send actual email via SMTP"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = user_email
            msg['Subject'] = "Your Security Code - SecurityApp"
            
            # Email body
            body = f"""
Your verification code is: {otp_code}

This code will expire at: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}
Valid for {self.otp_expiry_minutes} minutes from generation.

Do not share this code with anyone.

Best regards,
SecurityApp Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            security_logger.log_activity(
                action='otp_email_sent',
                status='success',
                details=f'Real email sent to {user_email}'
            )
            return True, "OTP sent to your email address"
            
        except Exception as e:
            security_logger.log_activity(
                action='otp_email_sent',
                status='failure',
                details=f'SMTP error: {str(e)}'
            )
            # Fallback to simulation if SMTP fails
            return self._simulate_email(user_email, otp_code, expires_at)
    
    def _simulate_email(self, user_email, otp_code, expires_at):
        """Simulate email delivery (console output)"""
        self.simulate_email_otp(user_email, otp_code, expires_at)
        return True, "OTP sent (simulated) - check console output"
    
    def send_otp(self, user_id):
        """Generate OTP and send via email - Missing method that main.py calls"""
        try:
            # Get user email
            user_query = "SELECT email FROM users WHERE id = ?"
            user_result = db.execute_query(user_query, (user_id,), fetch=True)
            
            if not user_result:
                return False, "User not found"
            
            user_email = user_result[0]['email']
            
            # Create OTP
            success, otp_code, expires_at = self.create_otp(user_id)
            
            if not success:
                return False, "Failed to generate OTP"
            
            # Send OTP email
            email_success, email_message = self.send_otp_email(user_email, otp_code, expires_at)
            
            if email_success:
                return True, f"OTP sent to {user_email}. {email_message}"
            else:
                return False, f"Failed to send OTP: {email_message}"
                
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='send_otp',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return False, f"OTP sending failed: {str(e)}"
    
    def generate_otp_code(self):
        """Generate 6-digit OTP code"""
        return str(secrets.randbelow(999999)).zfill(6)
    
    def generate_totp_secret(self):
        """Generate TOTP secret for user"""
        return pyotp.random_base32()
    
    def create_otp(self, user_id):
        """Create and store OTP code for user"""
        try:
            # Generate OTP code
            otp_code = self.generate_otp_code()
            expires_at = datetime.now() + timedelta(minutes=self.otp_expiry_minutes)
            
            # Store in database
            query = """
            INSERT INTO otp_codes (user_id, otp_code, expires_at)
            VALUES (?, ?, ?)
            """
            otp_id = db.execute_query(query, (user_id, otp_code, expires_at))
            
            if otp_id:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_generated',
                    status='success',
                    details=f'OTP expires at {expires_at}'
                )
                return True, otp_code, expires_at
            else:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_generated',
                    status='failure',
                    details='Database insertion failed'
                )
                return False, None, None
                
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='otp_generated',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return False, None, None
    
    def verify_otp(self, user_id, otp_code):
        """Verify OTP code for user"""
        try:
            # Get valid OTP codes for user
            query = """
            SELECT id, otp_code, expires_at 
            FROM otp_codes 
            WHERE user_id = ? AND used = 0 AND expires_at > datetime('now')
            ORDER BY created_at DESC
            """
            results = db.execute_query(query, (user_id,), fetch=True)
            
            if not results:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_verification',
                    status='failure',
                    details='No valid OTP codes found'
                )
                return False, "No valid OTP code found or code expired"
            
            # Check if provided code matches any valid code
            for otp_record in results:
                if otp_record['otp_code'] == otp_code:
                    # Mark OTP as used
                    update_query = "UPDATE otp_codes SET used = 1 WHERE id = ?"
                    db.execute_query(update_query, (otp_record['id'],))
                    
                    security_logger.log_activity(
                        user_id=user_id,
                        action='otp_verification',
                        status='success',
                        details='OTP verified successfully'
                    )
                    return True, "OTP verified successfully"
            
            # No matching code found
            security_logger.log_activity(
                user_id=user_id,
                action='otp_verification',
                status='failure',
                details=f'Invalid OTP code provided: {otp_code}'
            )
            return False, "Invalid OTP code"
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='otp_verification',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return False, f"OTP verification failed: {str(e)}"
    
    def setup_totp(self, user_email, issuer_name="SecurityApp"):
        """Setup TOTP for user and generate QR code"""
        try:
            # Generate TOTP secret
            secret = self.generate_totp_secret()
            
            # Create TOTP object
            totp = pyotp.TOTP(secret)
            
            # Generate provisioning URI for QR code
            provisioning_uri = totp.provisioning_uri(
                name=user_email,
                issuer_name=issuer_name
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64 for easy transmission
            img_buffer = io.BytesIO()
            qr_image.save(img_buffer, format='PNG')
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            security_logger.log_activity(
                action='totp_setup',
                status='success',
                details=f'TOTP setup for {user_email}'
            )
            
            return True, {
                'secret': secret,
                'qr_code_base64': img_base64,
                'provisioning_uri': provisioning_uri,
                'manual_entry_key': secret
            }
            
        except Exception as e:
            security_logger.log_activity(
                action='totp_setup',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return False, f"TOTP setup failed: {str(e)}"
    
    def verify_totp(self, secret, token):
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            
            # Verify token with window for clock skew
            is_valid = totp.verify(token, valid_window=1)
            
            if is_valid:
                security_logger.log_activity(
                    action='totp_verification',
                    status='success',
                    details='TOTP token verified'
                )
                return True, "TOTP token verified successfully"
            else:
                security_logger.log_activity(
                    action='totp_verification',
                    status='failure',
                    details=f'Invalid TOTP token: {token}'
                )
                return False, "Invalid TOTP token"
                
        except Exception as e:
            security_logger.log_activity(
                action='totp_verification',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return False, f"TOTP verification failed: {str(e)}"
    
    def cleanup_expired_otps(self):
        """Clean up expired OTP codes from database"""
        try:
            query = "DELETE FROM otp_codes WHERE expires_at < datetime('now')"
            deleted_count = db.execute_query(query)
            
            if deleted_count > 0:
                security_logger.log_activity(
                    action='otp_cleanup',
                    status='success',
                    details=f'Cleaned up {deleted_count} expired OTP codes'
                )
            
            return deleted_count
            
        except Exception as e:
            security_logger.log_activity(
                action='otp_cleanup',
                status='failure',
                details=f'Exception: {str(e)}'
            )
            return 0
    
    def simulate_email_otp(self, user_email, otp_code, expires_at):
        """Simulate email delivery of OTP code"""
        print("=" * 50)
        print("📧 EMAIL SIMULATION")
        print("=" * 50)
        print(f"To: {user_email}")
        print(f"Subject: Your Security Code - SecurityApp")
        print()
        print(f"Your verification code is: {otp_code}")
        print(f"This code will expire at: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Valid for {self.otp_expiry_minutes} minutes from generation.")
        print()
        print("Do not share this code with anyone.")
        print("=" * 50)
        
        security_logger.log_activity(
            action='email_simulation',
            status='success',
            details=f'OTP email simulated for {user_email}'
        )
    
    def get_current_totp(self, secret):
        """Get current TOTP code for testing purposes"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.now()
        except Exception:
            return None

mfa_manager = MFAManager() 