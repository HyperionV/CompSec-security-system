#!/usr/bin/env python3
"""
Admin Management Console

Simple console application for managing admin accounts.
Provides basic CRUD operations for admin users.

Usage:
    python create_admin.py
"""

import os
import sys
import sqlite3
import hashlib
import secrets
import getpass
from datetime import datetime

# Add the current directory to path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def generate_salt():
    """Generate cryptographically secure salt"""
    return secrets.token_hex(32)

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_recovery_code():
    """Generate recovery code"""
    return secrets.token_urlsafe(12)[:16].upper()

def hash_recovery_code(recovery_code):
    """Hash recovery code for secure storage"""
    return hashlib.sha256(recovery_code.encode()).hexdigest()

def get_all_admins(db_path):
    """Get all admin users"""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, name, created_at FROM users WHERE role = 'admin'")
            return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def get_user_by_email(db_path, email):
    """Get user by email"""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, name, role, created_at FROM users WHERE email = ?", (email,))
            return cursor.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def create_admin_user(db_path, email=None, password=None, name=None):
    """Create an admin user"""
    
    # Get input if not provided
    if not email:
        email = input("Enter admin email: ").strip()
    if not name:
        name = input("Enter admin name: ").strip()
    if not password:
        password = getpass.getpass("Enter admin password: ")
    
    # Check if user already exists
    if get_user_by_email(db_path, email):
        print(f"❌ User with email {email} already exists!")
        return False, None, None
    
    # Generate security components
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    recovery_code = generate_recovery_code()
    recovery_code_hash = hash_recovery_code(recovery_code)
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Create admin user
            cursor.execute("""
                INSERT INTO users (
                    email, name, phone, address, birth_date, 
                    password_hash, salt, role, recovery_code_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email,
                name,
                "+1-555-0000",  # Default phone
                "N/A",  # Default address
                "1990-01-01",  # Default birth date
                password_hash,
                salt,
                "admin",
                recovery_code_hash,
                datetime.now().isoformat()
            ))
            
            user_id = cursor.lastrowid
            
            # Log the admin creation
            cursor.execute("""
                INSERT INTO activity_logs (
                    user_id, action, status, details, timestamp
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                "ADMIN_ACCOUNT_CREATION",
                "success",
                f"Admin account created via console: {email}",
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
            return True, user_id, recovery_code
            
    except sqlite3.Error as e:
        print(f"Database error creating admin: {e}")
        return False, None, None
    except Exception as e:
        print(f"Unexpected error creating admin: {e}")
        return False, None, None

def delete_admin_user(db_path, email):
    """Delete an admin user"""
    try:
        user = get_user_by_email(db_path, email)
        if not user:
            print(f"❌ User {email} not found!")
            return False
        
        user_id, user_email, user_name, user_role, created_at = user
        
        if user_role != "admin":
            print(f"❌ User {email} is not an admin!")
            return False
        
        # Confirm deletion
        confirm = input(f"Are you sure you want to delete admin '{user_name}' ({email})? (y/N): ")
        if confirm.lower() != 'y':
            print("❌ Deletion cancelled.")
            return False
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Delete user
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            
            # Log the deletion
            cursor.execute("""
                INSERT INTO activity_logs (
                    user_id, action, status, details, timestamp
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                "ADMIN_ACCOUNT_DELETION",
                "success",
                f"Admin account deleted via console: {email}",
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
        print(f"✅ Admin user {email} deleted successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error deleting admin: {e}")
        return False

def reset_admin_password(db_path, email):
    """Reset admin password"""
    try:
        user = get_user_by_email(db_path, email)
        if not user:
            print(f"❌ User {email} not found!")
            return False
        
        user_id, user_email, user_name, user_role, created_at = user
        
        if user_role != "admin":
            print(f"❌ User {email} is not an admin!")
            return False
        
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("❌ Passwords don't match!")
            return False
        
        # Generate new security components
        salt = generate_salt()
        password_hash = hash_password(new_password, salt)
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Update password
            cursor.execute("""
                UPDATE users SET password_hash = ?, salt = ? WHERE id = ?
            """, (password_hash, salt, user_id))
            
            # Log the password reset
            cursor.execute("""
                INSERT INTO activity_logs (
                    user_id, action, status, details, timestamp
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                "ADMIN_PASSWORD_RESET",
                "success",
                f"Admin password reset via console: {email}",
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
        print(f"✅ Password for admin {email} reset successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error resetting password: {e}")
        return False

def ensure_database_initialized(db_path):
    """Ensure database and tables exist"""
    try:
        # Import the database manager to initialize tables
        from modules.database import DatabaseManager
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database (this will create tables if they don't exist)
        db_manager = DatabaseManager(db_path)
        print("✅ Database initialized successfully")
        return True
        
    except ImportError as e:
        print(f"❌ Error importing database module: {e}")
        print("Make sure you're running this script from the SecurityApp directory")
        return False
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return False

def show_menu():
    """Show main menu"""
    print("\n🔐 Admin Management Console")
    print("=" * 30)
    print("1. List all admin accounts")
    print("2. Create new admin account")
    print("3. Delete admin account")
    print("4. Reset admin password")
    print("5. Create default admin (admin@admin.com)")
    print("0. Exit")
    print("-" * 30)

def list_admins(db_path):
    """List all admin accounts"""
    admins = get_all_admins(db_path)
    if not admins:
        print("❌ No admin accounts found!")
        return
    
    print(f"\n📋 Admin Accounts ({len(admins)} found):")
    print("-" * 60)
    for admin in admins:
        user_id, email, name, created_at = admin
        print(f"ID: {user_id:<3} | {email:<25} | {name:<20} | {created_at[:10]}")

def create_default_admin(db_path):
    """Create default admin account"""
    print("\n👤 Creating default admin account...")
    success, user_id, recovery_code = create_admin_user(
        db_path, 
        email="admin@admin.com", 
        password="Admin@123", 
        name="System Administrator"
    )
    
    if success:
        print(f"✅ Default admin created successfully!")
        print(f"   User ID: {user_id}")
        print(f"   Email: admin@admin.com")
        print(f"   Password: Admin@123")
        print(f"   Recovery Code: {recovery_code}")
        print("\n⚠️  Change password after first login!")

def main():
    """Main console application"""
    print("🔐 Security Application - Admin Management Console")
    print("=" * 55)
    
    # Database path
    db_path = "security_app.db"
    data_db_path = "data/security_app.db"
    
    # Check if database exists in either location
    if os.path.exists(data_db_path):
        db_path = data_db_path
        print(f"📁 Using database: {db_path}")
    elif os.path.exists(db_path):
        print(f"📁 Using database: {db_path}")
    else:
        # Use data directory path and initialize
        db_path = data_db_path
        print(f"📁 Creating database: {db_path}")
        
        # Initialize database
        if not ensure_database_initialized(db_path):
            print("❌ Failed to initialize database. Exiting.")
            sys.exit(1)
    
    # Main menu loop
    while True:
        show_menu()
        try:
            choice = input("Enter your choice: ").strip()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
            elif choice == "1":
                list_admins(db_path)
            elif choice == "2":
                print("\n➕ Create New Admin Account")
                success, user_id, recovery_code = create_admin_user(db_path)
                if success:
                    print(f"✅ Admin created! ID: {user_id}, Recovery: {recovery_code}")
            elif choice == "3":
                print("\n🗑️  Delete Admin Account")
                email = input("Enter admin email to delete: ").strip()
                delete_admin_user(db_path, email)
            elif choice == "4":
                print("\n🔄 Reset Admin Password")
                email = input("Enter admin email: ").strip()
                reset_admin_password(db_path, email)
            elif choice == "5":
                create_default_admin(db_path)
            else:
                print("❌ Invalid choice! Please try again.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main() 