## Summary of Changes (dave-testing vs. main):

### gui/tabs/file_operations_tab.py:
- Updated imports to include PasswordDialog.
- Modified encrypt_file and decrypt_file calls to match the updated file_crypto method signatures (passing file_path, sender_user_id, output_format, encrypted_file_path, user_id, passphrase, key_file_path instead of previous arguments).
- Removed logic for auto-generating output filenames, as this is now handled internally by decrypt_file.
- Integrated a PasswordDialog for passphrase input during decryption.

### gui/tabs/key_management_tab.py:
- Adjusted latest_key retrieval to handle direct dictionary return from get_user_keys.
- Modified date string parsing for created_at and expires_at to replace spaces with 'T' for datetime.fromisoformat() compatibility.
- Updated date formatting for display in key_details.

### modules/auth.py:
- Imported the json module.
- Revised the change_passphrase method to correctly handle and re-encrypt the private key:
    - It now fetches a single key_record for the user.
    - Uses json.loads() to parse the encrypted_private_key from the database.
    - Correctly calls key_manager.decrypt_private_key with the parsed dictionary.
    - Calls key_manager.encrypt_private_key to re-encrypt with the new passphrase.
    - Calls self.db.update_key_encrypted_private_key to save the re-encrypted key.

### modules/database.py and modules/database_sqlite.py:
- Added a new method update_key_encrypted_private_key(self, key_id: int, encrypted_private_key_json: str) to update the encrypted private key for a given key ID in the database. This was crucial for the passphrase change functionality.

### modules/file_crypto.py:
- Corrected import path for InvalidKey and InvalidTag from cryptography.exceptions.
- Added DEBUG print statements to decrypt_file to show input parameters and general decryption failures.
- Implemented more granular try-except blocks around critical decryption steps (private_key.decrypt, session_key_decryption, decrypt_file_blocks, aesgcm.decrypt) to catch and log specific InvalidKey and InvalidTag exceptions, providing more detailed error messages.

### modules/key_manager.py:
- Added DEBUG print statements to decrypt_private_key to show lengths of salt, nonce, ciphertext, aes_key, and iterations before decryption.
- Added DEBUG print statements to store_keys_in_database and get_user_keys to inspect the JSON string of the encrypted private key at storage and retrieval.
- Modified the decrypt_private_key's exception handling to also print the type(e).__name__ for better debugging.

### modules/logger.py:
- Explicitly cast the details parameter to str when logging to the database to prevent type issues.

### requirements.txt:
- Changed cryptography version from ==41.0.8 to ==38.0.4.

This comprehensive set of changes addresses various bugs, improves error handling, and refines the cryptographic operations for key and file management.
