# QR Code Operations

This document details the QR Code Operations features of the Security Application, covering data flow, usage, and underlying security principles.

## 1. Data Flow (Class and Function Level)

### 1.1. Public Key QR Code Generation Flow

**Components Involved:**
- `gui/tabs/qr_operations_tab.py` (`QROperationsTab` class)
- `modules/qr_handler.py` (`QRCodeHandler` class)
- `modules/key_manager.py` (for retrieving user's public key)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `qrcode` library

**Sequence of Operations:**
1. **User Initiates QR Generation:** From `QROperationsTab`, the user clicks "Generate QR Code for My Public Key".
2. **`QROperationsTab.generate_qr_code`:**
   - Retrieves the current user's email from `user_session`.
   - Checks if the user has valid RSA keys by calling `db.get_user_keys_by_id`.
   - Prompts the user to select a save location for the PNG file.
   - Calls `qr_handler.generate_user_public_key_qr` (from `QRCodeHandler`) with the user's ID and email.
   - Handles saving the generated QR code image to the specified path.
3. **`QRCodeHandler.generate_user_public_key_qr` (`modules/qr_handler.py`):**
   - **Public Key Retrieval:** Calls `key_manager.get_user_public_key` to fetch the user's active public key from the database.
   - **Data Structuring:** Creates a string combining `email`, `creation_date`, and `base64`-encoded `public_key`.
   - **QR Code Creation:** Calls `generate_qr_code` with this structured data.
     - Uses `qrcode` library to create the QR code image.
     - Converts the image to `base64` for internal use.
     - Optionally saves the image to `data/qr_codes/` directory with a timestamped filename.
   - **Logging:** Logs QR code generation status via `security_logger.log_activity`.
   - **Returns:** Success status and a dictionary containing the base64 QR image, data, and optional filepath.
4. **`QROperationsTab.generate_qr_code` Response Handling:**
   - Displays success or error messages (using `show_info`, `show_error`).

### 1.2. Public Key QR Code Import Flow

**Components Involved:**
- `gui/tabs/qr_operations_tab.py` (`QROperationsTab` class)
- `modules/qr_handler.py` (`QRCodeHandler` class)
- `modules/public_key_manager.py` (for importing public keys)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)
- `modules/logger.py` (`SecurityLogger` class - accessed via `security_logger` alias)
- `Pillow` (PIL) and `pyzbar` libraries

**Sequence of Operations:**
1. **User Initiates QR Import:** From `QROperationsTab`, the user clicks "Import Public Key from QR Code".
2. **`QROperationsTab.import_qr_code`:**
   - Prompts the user to select a QR code image file using `get_open_file`.
   - Calls `qr_handler.import_public_key_from_qr` (from `QRCodeHandler`) with the current user's ID and the selected image path.
   - Refreshes the `Imported Public Keys` table (`refresh_data`).
3. **`QRCodeHandler.import_public_key_from_qr` (`modules/qr_handler.py`):**
   - **QR Code Reading:** Calls `read_qr_code`.
     - Uses `Pillow` to open the image and `pyzbar.decode` to read QR code data.
     - Logs QR code read status.
   - **Data Parsing:** Calls `read_public_key_qr` to parse the raw QR data (expected format: `email|creation_date|public_key_base64`).
   - **Public Key Import:** Calls `public_key_manager.import_public_key` (from `PublicKeyManager`) with the extracted email, public key, and current user's ID.
     - `PublicKeyManager` validates the public key format and stores it in the `public_keys` table via `db.execute_query`.
     - Logs the import status.
   - **Returns:** Success status and a message/result dictionary.
4. **`QROperationsTab.import_qr_code` Response Handling:**
   - Displays success or error messages.
   - Triggers `refresh_data` to update the table of imported public keys.

### 1.3. Public Key Search and Display Flow

**Components Involved:**
- `gui/tabs/qr_operations_tab.py` (`QROperationsTab` class)
- `modules/database.py` (`DatabaseManager` class - accessed via `db` alias)

**Sequence of Operations:**
1. **User Initiates Search/Refresh:** From `QROperationsTab`, the user types an email in the search field and clicks "Search", or clicks "Refresh".
2. **`QROperationsTab.search_keys` / `QROperationsTab.refresh_data`:**
   - **Search:** `search_keys` calls `db.search_public_key_by_email` to find keys matching the entered email for the current user.
   - **Refresh:** `refresh_data` calls `db.get_public_keys_by_user` to retrieve all public keys imported by the current user.
   - Clears and repopulates the `keys_table` with the fetched results using `add_key_to_table`.

## 2. How to Use the Feature

### 2.1. Generating Your Public Key QR Code
1. Navigate to the "QR Operations" tab in the main application.
2. In the "Generate QR Code" section, click the "Generate QR Code for My Public Key" button.
3. A "Save QR Code" dialog will appear. Choose a location and filename (e.g., `my_public_key_qr.png`).
4. Upon successful generation, a confirmation message will be displayed, and the QR code image file will be saved. You can then share this PNG image with others.

### 2.2. Importing a Public Key from a QR Code
1. Obtain a QR code image (PNG, JPG, JPEG, BMP) that contains someone else's public key.
2. Navigate to the "QR Operations" tab in the main application.
3. In the "Import Public Key from QR Code" section, click the "Import Public Key from QR Code" button.
4. A "Select QR Code Image" dialog will appear. Browse and select the QR code image file.
5. Upon successful import, a confirmation message will be displayed, and the newly imported public key will appear in the "Imported Public Keys" table.

### 2.3. Viewing Imported Public Keys
1. The "Imported Public Keys" table automatically displays all public keys you have imported.
2. You can use the "Email:" search field and "Search" button to filter the list by a specific email address.
3. Click the "Refresh" button to reload the entire list of imported public keys.

## 3. Technical Knowledge about Security

### 3.1. QR Code Data Structure for Public Keys
- **Mechanism:** Public keys are encoded into QR codes using a specific delimited string format: `email|creation_date|public_key_base64`. The `public_key` itself is `base64`-encoded to ensure it's safely representable within the QR code's data capacity. The `creation_date` is in `YYYY-MM-DD` format. This structured format facilitates reliable parsing upon import.
- **Purpose:** Standardizes the public key sharing mechanism, making it interoperable and less prone to errors during manual transfer. Encoding the public key in base64 prevents issues with special characters.
- **Relevance to Best Practices:** A well-defined data format for QR code payloads enhances the robustness and security of the key exchange process, reducing the risk of data corruption or misinterpretation.

### 3.2. Public Key Import Validation
- **Mechanism:** During import, the application validates the QR code's data structure (`len(parts) != 3`) and the base64 encoding of the public key. The `PublicKeyManager` (implicitly called by `import_public_key_from_qr`) also handles storing the key in the database and associating it with the importing user.
- **Purpose:** Prevents the import of malformed or malicious QR codes that could lead to application errors or security vulnerabilities. Ensures that only valid public keys are added to the user's keyring.
- **Relevance to Best Practices:** Input validation is a fundamental security practice. Ensuring the integrity and correct format of imported cryptographic material is crucial for maintaining the trust in the public key infrastructure within the application.

### 3.3. Offline Key Exchange through QR Codes
- **Mechanism:** QR codes enable an **offline** or **air-gapped** method for exchanging public keys. The QR code image can be displayed on one device and scanned by another, bypassing network transfers that might be intercepted.
- **Purpose:** Offers a highly secure method for initial public key exchange, especially in environments where direct network connectivity might be risky or unavailable. It reduces the attack surface associated with online key distribution.
- **Relevance to Best Practices:** Providing offline key exchange options enhances the overall security posture, especially for sensitive cryptographic operations. It aligns with principles of defense-in-depth.

### 3.4. Secure Storage of Imported Public Keys
- **Mechanism:** Imported public keys are stored in the application's SQLite database (specifically, in the `public_keys` table) and associated with the `user_id` who imported them. They are marked with an `is_active` status.
- **Purpose:** Centralized and persistent storage of trusted public keys allows for their easy retrieval and use in cryptographic operations (like file encryption or signature verification) without needing re-importation. Associating them with a user ensures proper multi-user segregation.
- **Relevance to Best Practices:** Secure storage of cryptographic materials, even public keys, is important to prevent tampering or unauthorized modification. A robust database schema ensures data integrity and proper access control. 