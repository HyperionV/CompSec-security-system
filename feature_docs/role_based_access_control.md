# Role-Based Access Control

This document details the Role-Based Access Control (RBAC) features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. User Role Assignment and Storage

**Components Involved:**
- `modules/auth.py` (`AuthManager` class, `GlobalUserSession` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)

**Sequence of Operations:**
1. **User Registration (`AuthManager.register_user`):**
   - When a new user registers, their `role` is implicitly set to 'user' by default in the `users` table during insertion.
   - There is no direct role assignment mechanism for `admin` during registration.
2. **Admin Role Assignment (Implicit/Manual):**
   - The application likely has a mechanism (e.g., initial setup script, direct database modification, or another hidden admin function) to designate at least one user as `admin`.
   - Once a user's `role` in the `users` table is set to 'admin', the system recognizes them as an administrator.

### 1.2. Access Control Enforcement Flow

**Components Involved:**
- `gui/main_app_screen.py` (or main window that loads tabs)
- `gui/tabs/admin_tab.py` (`AdminTab` class)
- `modules/auth.py` (`GlobalUserSession` class)

**Sequence of Operations:**
1. **User Login:** Upon successful login, `AuthManager.initiate_login_flow` or `AuthManager.complete_login_with_mfa` populates the `GlobalUserSession` with the `user_info`, including their `role`.
2. **Tab Loading/Visibility (`main_app_screen.py` or `main_window.py`):**
   - When the main application loads its tabs (e.g., in `main_app_screen.py`), it checks the `role` of the `current_user` from `GlobalUserSession`.
   - **Admin Tab Restriction:** The `admin_tab.py` (`AdminTab`) is specifically designed to be accessible **only** to users with the `admin` role.
     - The logic to enable/disable or hide the admin tab based on the user's role would reside in the parent component (e.g., `main_app_screen.py` or `main_window.py`) responsible for managing tab visibility.
     - Inside `AdminTab` itself, methods like `lock_user_account` and `unlock_user_account` perform an explicit check: `if self.user_session.user_info.get('role') != 'admin': show_error(...)` to ensure only admins can perform these actions, even if the GUI element was somehow exposed.
3. **Action-Specific Role Checks:**
   - Certain actions within the `AdminTab` (e.g., locking/unlocking user accounts) directly invoke methods that re-verify the user's role (`lock_user_account`, `unlock_user_account` in `AdminTab` call `self.user_session.user_info.get('role')`).
   - These methods then interact with the `DatabaseManager` (`db.lock_account`, `db.unlock_account`) to perform the administrative database operations.

### 1.3. User Account Management by Admin Flow

**Components Involved:**
- `gui/tabs/admin_tab.py` (`AdminTab` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)

**Sequence of Operations:**
1. **Admin Views Users:** In `AdminTab`, `refresh_data` calls `db.get_all_users_for_admin` to populate the `users_table` with all system users and their roles/statuses.
2. **Admin Locks/Unlocks Account:**
   - Admin clicks "Lock" or "Unlock" button next to a user in the `users_table`.
   - `AdminTab.lock_user_account` or `AdminTab.unlock_user_account` is called.
   - **Role Re-check:** These methods first verify `self.user_session.user_info.get('role') == 'admin'` and prevent self-locking.
   - **Database Update:** Calls `db.lock_account(user_id)` or `db.unlock_account(user_id)` to update the `is_locked` status in the `users` table.
   - **Logging:** Logs the administrative action (`user_account_locked`, `user_account_unlocked`) via `security_logger.log_activity`.
   - **Returns:** Success status and updates the UI.

## 2. How to Use the Feature

### 2.1. Accessing Admin Functions
1. Log in to the application with an account that has been assigned the `admin` role.
2. Upon successful login, the `AdminTab` will be visible and accessible in the main application interface (e.g., as a tab).
3. Non-admin users will not see or be able to access the `AdminTab`.

### 2.2. Managing User Accounts (Admin Only)
1. Navigate to the "Admin" tab.
2. The "System Users" table will display a list of all registered users, their emails, roles, and current statuses (Active/Locked).
3. To **lock a user account**:
   - Find the desired user in the table.
   - Click the "Lock" button next to their entry.
   - Confirm the action in the prompt.
   - The user's status will change to "Locked", preventing them from logging in.
4. To **unlock a user account**:
   - Find the desired user in the table.
   - Click the "Unlock" button next to their entry.
   - Confirm the action in the prompt.
   - The user's status will change to "Active", allowing them to log in again.

### 2.3. Viewing System Information (Admin Only)
1. In the "Admin" tab, the "System Information" section displays overall statistics, such as total users, total keys, total public keys, and recent activity logs count.
2. Click the "View System Logs" button to open a dialog displaying recent security audit logs, providing an overview of system activities and potential security events.

## 3. Technical Knowledge about Security

### 3.1. Role-Based Access Control (RBAC) Principles
- **Mechanism:** RBAC is implemented by assigning specific `roles` (e.g., `user`, `admin`) to users. Permissions to access resources or perform actions are then tied to these roles, rather than directly to individual users. The application differentiates between `user` and `admin` roles, restricting access to sensitive features (like the `AdminTab` and its functions) to `admin` users only.
- **Purpose:** Simplifies security management by centralizing permissions around roles. It ensures that users only have the minimum necessary privileges (`least privilege principle`) to perform their tasks, reducing the risk of unauthorized access or actions.
- **Relevance to Best Practices:** RBAC is a fundamental security model widely adopted for managing access in applications, promoting a structured and scalable approach to security policy enforcement.

### 3.2. Separation of Duties
- **Mechanism:** The `admin` role is distinct from the regular `user` role, and functions like account locking/unlocking and log viewing are exclusively assigned to administrators. Furthermore, an admin cannot lock their own account.
- **Purpose:** Prevents a single individual from having excessive control that could be exploited for malicious purposes or lead to errors. It introduces checks and balances, requiring different roles for different critical actions.
- **Relevance to Best Practices:** Enforcing separation of duties is a key organizational security control that helps mitigate insider threats and prevent fraud or abuse of privileges.

### 3.3. Secure Privilege Enforcement
- **Mechanism:** Privilege checks are performed not only at the UI level (hiding/disabling `AdminTab` for regular users) but also at the application logic layer (e.g., `AdminTab.lock_user_account` re-verifying `user_session.user_info.get('role')`). This multi-layered enforcement prevents unauthorized actions even if a malicious user bypasses the UI controls.
- **Purpose:** Provides a defense-in-depth approach to access control. Relying solely on UI restrictions is insecure, as these can be bypassed. Backend checks ensure that security decisions are made authoritatively.
- **Relevance to Best Practices:** Essential for robust security. Authorization checks should always be performed on the server-side or in the core business logic, not just at the user interface, to prevent privilege escalation.

### 3.4. Audit Logging of Administrative Actions
- **Mechanism:** All administrative actions (e.g., locking/unlocking accounts, viewing logs) are meticulously recorded in the security audit logs (`modules/logger.py`, `logs/security.log`). These logs include `timestamp`, `level`, `user_id`, `action`, `details`, and `status`.
- **Purpose:** Provides an immutable record of who did what, when, and with what outcome. This is crucial for forensic investigations, compliance auditing, and detecting suspicious activity. It holds administrators accountable for their actions.
- **Relevance to Best Practices:** Comprehensive and tamper-evident audit trails are vital for accountability, incident response, and meeting regulatory compliance requirements. 