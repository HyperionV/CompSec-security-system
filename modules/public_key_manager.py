import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

class PublicKeyManager:
    def __init__(self, user_email, database, logger):
        self.user_email = user_email
        self.database = database
        self.logger = logger
    
    def search_keys_by_email(self, search_email):
        try:
            # Search in both user's own keys and imported public keys
            results = []
            
            # Get user's own keys if searching for own email
            if search_email.lower() == self.user_email.lower():
                own_keys = self.database.get_user_keys(self.user_email)
                for key_data in own_keys:
                    if key_data:
                        results.append({
                            'email': self.user_email,
                            'public_key': key_data[0],
                            'created_at': key_data[1],
                            'expires_at': key_data[2],
                            'source': 'own_key',
                            'key_id': key_data[3] if len(key_data) > 3 else None
                        })
            
            # Search imported public keys
            imported_keys = self.database.search_public_keys_by_email(search_email)
            for key_data in imported_keys:
                results.append({
                    'email': key_data[1],  # email from public_keys table
                    'public_key': key_data[2],  # public_key
                    'created_at': key_data[3],  # created_at
                    'expires_at': None,  # Will be calculated
                    'source': 'imported',
                    'key_id': key_data[0]  # id from public_keys table
                })
            
            self.logger.log_action(
                self.user_email, 
                "public_key_search", 
                "success", 
                f"Searched for keys: {search_email}, found {len(results)} results"
            )
            
            return True, results
            
        except Exception as e:
            self.logger.log_action(
                self.user_email, 
                "public_key_search", 
                "error", 
                f"Search failed for {search_email}: {str(e)}"
            )
            return False, f"Search failed: {str(e)}"
    
    def get_all_available_keys(self):
        try:
            results = []
            
            # Get user's own keys
            own_keys = self.database.get_user_keys(self.user_email)
            for key_data in own_keys:
                if key_data:
                    results.append({
                        'email': self.user_email,
                        'public_key': key_data[0],
                        'created_at': key_data[1],
                        'expires_at': key_data[2],
                        'source': 'own_key',
                        'key_id': key_data[3] if len(key_data) > 3 else None
                    })
            
            # Get all imported public keys
            imported_keys = self.database.get_all_imported_public_keys(self.user_email)
            for key_data in imported_keys:
                results.append({
                    'email': key_data[1],
                    'public_key': key_data[2],
                    'created_at': key_data[3],
                    'expires_at': None,
                    'source': 'imported',
                    'key_id': key_data[0]
                })
            
            self.logger.log_action(
                self.user_email, 
                "list_all_keys", 
                "success", 
                f"Listed all available keys: {len(results)} total"
            )
            
            return True, results
            
        except Exception as e:
            self.logger.log_action(
                self.user_email, 
                "list_all_keys", 
                "error", 
                f"Failed to list keys: {str(e)}"
            )
            return False, f"Failed to retrieve keys: {str(e)}"
    
    def compute_key_status(self, created_at, expires_at=None):
        now = datetime.now()
        
        # For imported keys, calculate 90-day expiry from creation
        if expires_at is None:
            expires_at = created_at + timedelta(days=90)
        
        if expires_at < now:
            return "expired"
        elif (expires_at - now).days <= 7:
            return "expiring_soon"
        else:
            return "valid"
    
    def format_key_display(self, key_info):
        status = self.compute_key_status(key_info['created_at'], key_info['expires_at'])
        
        # Calculate expiry date for display
        if key_info['expires_at']:
            expiry_date = key_info['expires_at']
        else:
            expiry_date = key_info['created_at'] + timedelta(days=90)
        
        status_symbol = {
            'valid': '✓',
            'expiring_soon': '⚠️',
            'expired': '✗'
        }.get(status, '?')
        
        days_remaining = (expiry_date - datetime.now()).days
        
        return {
            'email': key_info['email'],
            'created_date': key_info['created_at'].strftime('%Y-%m-%d'),
            'expiry_date': expiry_date.strftime('%Y-%m-%d'),
            'status': status,
            'status_symbol': status_symbol,
            'days_remaining': max(0, days_remaining),
            'source': key_info['source'],
            'key_id': key_info['key_id']
        }
    
    def get_valid_recipients_for_encryption(self):
        success, all_keys = self.get_all_available_keys()
        if not success:
            return False, all_keys
        
        valid_recipients = []
        for key_info in all_keys:
            status = self.compute_key_status(key_info['created_at'], key_info['expires_at'])
            if status in ['valid', 'expiring_soon']:  # Allow expiring soon for encryption
                display_info = self.format_key_display(key_info)
                valid_recipients.append({
                    'email': key_info['email'],
                    'display': f"{key_info['email']} ({display_info['status_symbol']} {status.replace('_', ' ').title()})",
                    'public_key': key_info['public_key'],
                    'status': status
                })
        
        return True, valid_recipients
    
    def validate_public_key(self, public_key_data):
        try:
            # Try to load the public key to validate format
            if isinstance(public_key_data, str):
                public_key_data = public_key_data.encode()
            
            public_key = serialization.load_pem_public_key(public_key_data)
            return True, "Valid public key"
        except Exception as e:
            return False, f"Invalid public key format: {str(e)}" 