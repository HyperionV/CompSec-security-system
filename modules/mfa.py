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
from .auth import global_user_session

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
            details=f'SMTP configured for {server}:{port}',
            email=None  # System configuration, not user-specific
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
                details=f'Real email sent to {user_email}',
                email=user_email
            )
            return True, "OTP sent to your email address"
            
        except Exception as e:
            security_logger.log_activity(
                action='otp_email_sent',
                status='failure',
                details=f'SMTP error: {str(e)}',
                email=user_email
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
            # Try to get user email for logging
            try:
                user_query = "SELECT email FROM users WHERE id = ?"
                user_result = db.execute_query(user_query, (user_id,), fetch=True)
                user_email = user_result[0]['email'] if user_result else None
            except:
                user_email = None
                
            security_logger.log_activity(
                user_id=user_id,
                action='send_otp',
                status='failure',
                details=f'Exception: {str(e)}',
                email=user_email
            )
            return False, f"OTP sending failed: {str(e)}"
    
    def generate_otp(self, user_id):
        """Generate OTP and send via email - Method expected by GUI"""
        try:
            # Get user email
            user_query = "SELECT email FROM users WHERE id = ?"
            user_result = db.execute_query(user_query, (user_id,), fetch=True)
            
            if not user_result:
                return False, "User not found", None
            
            user_email = user_result[0]['email']
            
            # Create OTP
            success, otp_code, expires_at = self.create_otp(user_id)
            
            if not success:
                return False, "Failed to generate OTP", None
            
            # Send OTP email
            email_success, email_message = self.send_otp_email(user_email, otp_code, expires_at)
            
            # Prepare OTP data for GUI (includes code for testing)
            otp_data = {
                'otp_code': otp_code,
                'expires_at': expires_at,
                'user_email': user_email
            }
            
            if email_success:
                return True, f"OTP sent to {user_email}. {email_message}", otp_data
            else:
                return False, f"Failed to send OTP: {email_message}", None
                
        except Exception as e:
            # Try to get user email for logging
            try:
                user_query = "SELECT email FROM users WHERE id = ?"
                user_result = db.execute_query(user_query, (user_id,), fetch=True)
                user_email = user_result[0]['email'] if user_result else None
            except:
                user_email = None
                
            security_logger.log_activity(
                user_id=user_id,
                action='generate_otp',
                status='failure',
                details=f'Exception: {str(e)}',
                email=user_email
            )
            return False, f"OTP generation failed: {str(e)}", None
    
    def generate_otp_code(self):
        """Generate 6-digit OTP code"""
        return pyotp.HOTP(pyotp.random_base32()).at(secrets.randbelow(9999999))
    
    def generate_totp_secret(self):
        """Generate TOTP secret for user"""
        return pyotp.random_base32()
    
    def create_otp(self, user_id):
        """Create and store OTP code for user"""
        try:
            # Get user email first for logging
            user_query = "SELECT email FROM users WHERE id = ?"
            user_result = db.execute_query(user_query, (user_id,), fetch=True)
            user_email = user_result[0]['email'] if user_result else None
            
            # Generate OTP code
            otp_code = self.generate_otp_code()
            expires_at = datetime.now() + timedelta(minutes=self.otp_expiry_minutes)
            
            # Store in database - explicitly set used = 0, format datetime for SQLite
            query = """
            INSERT INTO otp_codes (user_id, otp_code, expires_at, used)
            VALUES (?, ?, ?, 0)
            """
            # Format datetime for SQLite compatibility
            expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            otp_id = db.execute_query(query, (user_id, otp_code, expires_at_str))
            
            # Debug: Verify the OTP was actually inserted
            verify_query = "SELECT * FROM otp_codes WHERE user_id = ? AND otp_code = ?"
            verify_result = db.execute_query(verify_query, (user_id, otp_code), fetch=True)
            print(f"DEBUG: OTP inserted for user {user_id}, code {otp_code}, found in DB: {len(verify_result) if verify_result else 0}")
            if verify_result:
                print(f"DEBUG: Inserted OTP record: {verify_result[0]}")
            
            if otp_id:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_generated',
                    status='success',
                    details=f'OTP expires at {expires_at}',
                    email=user_email
                )
                return True, otp_code, expires_at
            else:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_generated',
                    status='failure',
                    details='Database insertion failed',
                    email=user_email
                )
                return False, None, None
                
        except Exception as e:
            # Try to get user email for logging even in exception case
            try:
                user_query = "SELECT email FROM users WHERE id = ?"
                user_result = db.execute_query(user_query, (user_id,), fetch=True)
                user_email = user_result[0]['email'] if user_result else None
            except:
                user_email = None
                
            security_logger.log_activity(
                user_id=user_id,
                action='otp_generated',
                status='failure',
                details=f'Exception: {str(e)}',
                email=user_email
            )
            print(f"DEBUG: Exception in create_otp: {str(e)}")
            return False, None, None
    
    def verify_otp(self, user_id, otp_code):
        """Verify OTP code for user"""
        try:
            # Get user email first for logging
            user_query = "SELECT email FROM users WHERE id = ?"
            user_result = db.execute_query(user_query, (user_id,), fetch=True)
            user_email = user_result[0]['email'] if user_result else None
            
            # Debug: First check all OTP codes for this user
            debug_query = "SELECT * FROM otp_codes WHERE user_id = ?"
            debug_results = db.execute_query(debug_query, (user_id,), fetch=True)
            print(f"DEBUG: All OTP codes for user {user_id}: {debug_results}")
            
            # Get current time for comparison
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"DEBUG: Current time: {current_time}")
            
            # Get valid OTP codes for user - use string comparison for SQLite
            query = """
            SELECT id, otp_code, expires_at 
            FROM otp_codes 
            WHERE user_id = ? AND used = 0 AND expires_at > ?
            ORDER BY created_at DESC
            """
            results = db.execute_query(query, (user_id, current_time), fetch=True)
            
            print(f"DEBUG: Valid OTP codes found: {len(results) if results else 0}")
            if results:
                print(f"DEBUG: OTP codes: {results}")
            
            if not results:
                security_logger.log_activity(
                    user_id=user_id,
                    action='otp_verification',
                    status='failure',
                    details='No valid OTP codes found',
                    email=user_email
                )
                return False, "No valid OTP code found or code expired"
            
            # Check if provided code matches any valid code
            print(f"DEBUG: Looking for OTP code: '{otp_code}'")
            for otp_record in results:
                print(f"DEBUG: Comparing with DB code: '{otp_record['otp_code']}'")
                if otp_record['otp_code'] == otp_code:
                    # Mark OTP as used
                    update_query = "UPDATE otp_codes SET used = 1 WHERE id = ?"
                    db.execute_query(update_query, (otp_record['id'],))
                    
                    security_logger.log_activity(
                        user_id=user_id,
                        action='otp_verification',
                        status='success',
                        details='OTP verified successfully',
                        email=user_email
                    )
                    return True, "OTP verified successfully"
            
            # No matching code found
            security_logger.log_activity(
                user_id=user_id,
                action='otp_verification',
                status='failure',
                details=f'Invalid OTP code provided: {otp_code}',
                email=user_email
            )
            return False, "Invalid OTP code"
            
        except Exception as e:
            # Try to get user email for logging even in exception case
            try:
                user_query = "SELECT email FROM users WHERE id = ?"
                user_result = db.execute_query(user_query, (user_id,), fetch=True)
                user_email = user_result[0]['email'] if user_result else None
            except:
                user_email = None
                
            security_logger.log_activity(
                user_id=user_id,
                action='otp_verification',
                status='failure',
                details=f'Exception: {str(e)}',
                email=user_email
            )
            print(f"DEBUG: Exception in verify_otp: {str(e)}")
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
                details=f'TOTP setup for {user_email}',
                email=user_email
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
                details=f'Exception: {str(e)}',
                email=user_email
            )
            return False, f"TOTP setup failed: {str(e)}"
    
    def setup_user_totp(self, user_id, user_email):
        """Setup TOTP for a specific user and store in database"""
        try:
            # Check if user already has TOTP setup
            if db.has_totp_setup(user_id):
                return False, "TOTP already setup for this user"
            
            # Setup TOTP
            success, totp_data = self.setup_totp(user_email)
            
            if not success:
                return False, totp_data
            
            # Store secret in database
            store_success = db.store_totp_secret(user_id, totp_data['secret'])
            
            if store_success:
                security_logger.log_activity(
                    user_id=user_id,
                    action='totp_user_setup',
                    status='success',
                    details=f'TOTP setup and stored for user {user_email}',
                    email=user_email
                )
                return True, totp_data
            else:
                return False, "Failed to store TOTP secret"
                
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='totp_user_setup',
                status='failure',
                details=f'Exception: {str(e)}',
                email=user_email
            )
            return False, f"TOTP setup failed: {str(e)}"
    
    def verify_user_totp(self, user_id, token):
        """Verify TOTP token for a specific user"""
        try:
            # Get user's TOTP secret
            secret = db.get_totp_secret(user_id)
            
            if not secret:
                return False, "TOTP not setup for this user"
            
            # Verify token
            return self.verify_totp(secret, token)
            
        except Exception as e:
            security_logger.log_activity(
                user_id=user_id,
                action='totp_user_verification',
                status='failure',
                details=f'Exception: {str(e)}',
                email=None
            )
            return False, f"TOTP verification failed: {str(e)}"
    
    def has_totp_setup(self, user_id):
        """Check if user has TOTP setup"""
        return db.has_totp_setup(user_id)
    
    def get_user_totp_qr(self, user_id, user_email):
        """Get TOTP QR code for existing user"""
        try:
            secret = db.get_totp_secret(user_id)
            
            if not secret:
                return False, "TOTP not setup for this user"
            
            # Create TOTP object
            totp = pyotp.TOTP(secret)
            
            # Generate provisioning URI for QR code
            provisioning_uri = totp.provisioning_uri(
                name=user_email,
                issuer_name="SecurityApp"
            )
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            img_buffer = io.BytesIO()
            qr_image.save(img_buffer, format='PNG')
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            return True, {
                'qr_code_base64': img_base64,
                'secret': secret
            }
            
        except Exception as e:
            return False, f"Failed to generate QR code: {str(e)}"
    
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
                    details='TOTP token verified',
                    email=global_user_session.get_current_user_email()
                )
                return True, "TOTP token verified successfully"
            else:
                security_logger.log_activity(
                    action='totp_verification',
                    status='failure',
                    details=f'Invalid TOTP token: {token}',
                    email=global_user_session.get_current_user_email()
                )
                return False, "Invalid TOTP token"
                
        except Exception as e:
            security_logger.log_activity(
                action='totp_verification',
                status='failure',
                details=f'Exception: {str(e)}',
                email=global_user_session.get_current_user_email()
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
                    details=f'Cleaned up {deleted_count} expired OTP codes',
                    email=None
                )
            
            return deleted_count
            
        except Exception as e:
            security_logger.log_activity(
                action='otp_cleanup',
                status='failure',
                details=f'Exception: {str(e)}',
                email=None
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
            details=f'OTP email simulated for {user_email}',
            email=user_email
        )
    
    def get_current_totp(self, secret):
        """Get current TOTP code for testing purposes"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.now()
        except Exception:
            return None

mfa_manager = MFAManager() 