import hmac
from datetime import datetime
from modules.logger import log_auth_success, log_auth_failure, security_logger

class SessionManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.current_user = None
            cls._instance.login_time = None
            cls._instance.is_authenticated = False
        return cls._instance
    
    def login(self, user_data):
        self.current_user = {
            'id': user_data[0],
            'email': user_data[1], 
            'name': user_data[2],
            'role': user_data[6],
            'created_at': user_data[7]
        }
        self.login_time = datetime.now()
        self.is_authenticated = True
        log_auth_success(user_data[1], f"Session started at {self.login_time}")
    
    def logout(self):
        if self.current_user:
            security_logger.log_logout(self.current_user['email'], "Session ended")
            self.current_user = None
            self.login_time = None
            self.is_authenticated = False
    
    def get_current_user(self):
        return self.current_user
    
    def is_logged_in(self):
        return self.is_authenticated and self.current_user is not None
    
    def has_role(self, role):
        if not self.is_logged_in():
            return False
        return self.current_user.get('role') == role
    
    def get_user_email(self):
        if self.is_logged_in():
            return self.current_user['email']
        return None

session_manager = SessionManager() 