import keyring

# --- Keyring Constants ---
# Use a single service name for both CLI and GUI to unify keychain access.
SHARED_KEYRING_SERVICE_NAME = "BambuStudioHelper"

# Keys for storing different pieces of information
# For tokens (used by both CLI and GUI for session management)
KEY_ACCESS_TOKEN_PREFIX = "access_token_for_" # Suffix with email: access_token_for_user@example.com
KEY_LAST_TOKEN_USER_EMAIL = "last_token_user_email" # Stores the email of the user whose token was last saved

# For GUI-specific "save credentials" feature
KEY_USER_EMAIL_GUI = "gui_user_email"
KEY_USER_PASSWORD_GUI = "gui_user_password" # Encrypted by OS keychain
KEY_PRINTER_SERIAL_GUI = "gui_printer_serial"


class KeychainManager:
    def __init__(self, service_name=SHARED_KEYRING_SERVICE_NAME):
        self.service_name = service_name

    def _get_token_key_for_email(self, email: str) -> str:
        """Generates a unique keyring key for storing a token associated with an email."""
        if not email:
            raise ValueError("Email cannot be empty when forming token key.")
        return f"{KEY_ACCESS_TOKEN_PREFIX}{email.lower()}"

    # --- Token Management (CLI and GUI) ---
    def save_token(self, email: str, token: str):
        """Saves an access token, associating it with an email."""
        if not email or not token:
            # print("Email and token are required to save.") # Or raise error
            return
        try:
            token_key = self._get_token_key_for_email(email)
            keyring.set_password(self.service_name, token_key, token)
            # Optionally, store the email of the last user whose token was saved
            keyring.set_password(self.service_name, KEY_LAST_TOKEN_USER_EMAIL, email)
            # print(f"Token for {email} saved to keychain.")
        except Exception as e:
            print(f"Error saving token to keychain: {e}") # Consider logging or specific error handling

    def load_token(self, email: str) -> str | None:
        """Loads an access token associated with an email."""
        if not email:
            return None
        try:
            token_key = self._get_token_key_for_email(email)
            return keyring.get_password(self.service_name, token_key)
        except Exception as e:
            print(f"Error loading token from keychain: {e}")
            return None

    def clear_token(self, email: str):
        """Clears an access token associated with an email."""
        if not email:
            return
        try:
            token_key = self._get_token_key_for_email(email)
            if keyring.get_password(self.service_name, token_key): # Check if exists
                keyring.delete_password(self.service_name, token_key)
                # print(f"Token for {email} cleared from keychain.")

            # If this was the last user, clear that reference too
            last_user = keyring.get_password(self.service_name, KEY_LAST_TOKEN_USER_EMAIL)
            if last_user == email:
                if keyring.get_password(self.service_name, KEY_LAST_TOKEN_USER_EMAIL): # Check if exists
                    keyring.delete_password(self.service_name, KEY_LAST_TOKEN_USER_EMAIL)
        except Exception as e:
            print(f"Error clearing token from keychain: {e}")

    def get_last_saved_token_email(self) -> str | None:
        """Gets the email of the user whose token was last saved."""
        try:
            return keyring.get_password(self.service_name, KEY_LAST_TOKEN_USER_EMAIL)
        except Exception as e:
            print(f"Error retrieving last token user email: {e}")
            return None

    # --- GUI Credential Management ---
    def save_gui_credentials(self, email: str | None, password: str | None, serial: str | None):
        """Saves GUI credentials (email, password, serial). Intended for 'Save Credentials' feature."""
        try:
            if email is not None: # Allow saving empty string to clear, but None means no change
                keyring.set_password(self.service_name, KEY_USER_EMAIL_GUI, email)
            if password is not None:
                keyring.set_password(self.service_name, KEY_USER_PASSWORD_GUI, password)
            if serial is not None:
                keyring.set_password(self.service_name, KEY_PRINTER_SERIAL_GUI, serial)
            # print("GUI credentials saved to keychain.")
        except Exception as e:
            print(f"Error saving GUI credentials to keychain: {e}")

    def load_gui_credentials(self) -> dict:
        """Loads GUI credentials (email, password, serial)."""
        try:
            email = keyring.get_password(self.service_name, KEY_USER_EMAIL_GUI)
            password = keyring.get_password(self.service_name, KEY_USER_PASSWORD_GUI)
            serial = keyring.get_password(self.service_name, KEY_PRINTER_SERIAL_GUI)
            return {"email": email, "password": password, "serial": serial}
        except Exception as e:
            print(f"Error loading GUI credentials from keychain: {e}")
            return {"email": None, "password": None, "serial": None}

    def clear_gui_credentials(self):
        """Clears all saved GUI credentials."""
        try:
            if keyring.get_password(self.service_name, KEY_USER_EMAIL_GUI):
                keyring.delete_password(self.service_name, KEY_USER_EMAIL_GUI)
            if keyring.get_password(self.service_name, KEY_USER_PASSWORD_GUI):
                keyring.delete_password(self.service_name, KEY_USER_PASSWORD_GUI)
            if keyring.get_password(self.service_name, KEY_PRINTER_SERIAL_GUI):
                keyring.delete_password(self.service_name, KEY_PRINTER_SERIAL_GUI)
            # print("GUI credentials cleared from keychain.")
        except Exception as e:
            print(f"Error clearing GUI credentials from keychain: {e}")

    def clear_all_for_email(self, email: str):
        """Clears token and GUI credentials associated with a specific email.
           Note: GUI credentials are not directly tied to email in this model,
           but if the stored GUI email matches, they will be cleared.
        """
        self.clear_token(email)
        gui_creds = self.load_gui_credentials()
        if gui_creds.get("email") == email:
            self.clear_gui_credentials()

    def clear_all_keychain_entries(self):
        """
        Clears ALL entries associated with this service_name.
        This is a more aggressive clear, useful for complete logout or reset.
        It iterates through known keys and attempts to delete them.
        It also attempts to delete any token keys by iterating if a last saved email is known.
        """
        print(f"Attempting to clear all keychain entries for service: {self.service_name}")
        keys_to_clear = [
            KEY_LAST_TOKEN_USER_EMAIL,
            KEY_USER_EMAIL_GUI,
            KEY_USER_PASSWORD_GUI,
            KEY_PRINTER_SERIAL_GUI
        ]
        # Attempt to clear token for last known user
        last_email = self.get_last_saved_token_email()
        if last_email:
            keys_to_clear.append(self._get_token_key_for_email(last_email))

        for key in keys_to_clear:
            try:
                password = keyring.get_password(self.service_name, key)
                if password is not None:
                    keyring.delete_password(self.service_name, key)
                    # print(f"Deleted key: {key}")
                # else:
                    # print(f"Key not found or no password set, skipping: {key}")
            except Exception as e: # Catching broad exception from keyring, e.g., if backend not available
                print(f"Error deleting key {key} from keychain: {e}")
        # print("Finished attempting to clear all known keychain entries.")

# Example Usage (optional, for testing this file directly)
if __name__ == "__main__":
    manager = KeychainManager()

    test_email = "test@example.com"
    test_token = "sample_token_12345"
    test_password = "sample_password"
    test_serial = "sample_serial"

    print(f"Using service name: {manager.service_name}")

    print("\n--- Testing Token Management ---")
    manager.save_token(test_email, test_token)
    loaded_token = manager.load_token(test_email)
    print(f"Loaded token for {test_email}: {loaded_token}")
    assert loaded_token == test_token

    last_email = manager.get_last_saved_token_email()
    print(f"Last saved token email: {last_email}")
    assert last_email == test_email

    print("\n--- Testing GUI Credential Management ---")
    manager.save_gui_credentials(test_email, test_password, test_serial)
    creds = manager.load_gui_credentials()
    print(f"Loaded GUI credentials: {creds}")
    assert creds["email"] == test_email
    assert creds["password"] == test_password
    assert creds["serial"] == test_serial

    print("\n--- Clearing Data ---")
    # manager.clear_token(test_email)
    # loaded_token_after_clear = manager.load_token(test_email)
    # print(f"Token for {test_email} after clear: {loaded_token_after_clear}")
    # assert loaded_token_after_clear is None

    # manager.clear_gui_credentials()
    # creds_after_clear = manager.load_gui_credentials()
    # print(f"GUI credentials after clear: {creds_after_clear}")
    # assert creds_after_clear["email"] is None
    # assert creds_after_clear["password"] is None
    # assert creds_after_clear["serial"] is None

    # Test clearing all
    manager.clear_all_keychain_entries()
    loaded_token_after_full_clear = manager.load_token(test_email)
    creds_after_full_clear = manager.load_gui_credentials()
    last_email_after_full_clear = manager.get_last_saved_token_email()

    print(f"Token for {test_email} after full clear: {loaded_token_after_full_clear}")
    print(f"GUI credentials after full clear: {creds_after_full_clear}")
    print(f"Last saved token email after full clear: {last_email_after_full_clear}")

    assert loaded_token_after_full_clear is None
    assert creds_after_full_clear["email"] is None
    assert creds_after_full_clear["password"] is None
    assert creds_after_full_clear["serial"] is None
    assert last_email_after_full_clear is None


    print("\n--- Test saving token for another user ---")
    test_email_2 = "another@example.com"
    test_token_2 = "another_token_67890"
    manager.save_token(test_email_2, test_token_2)
    loaded_token_2 = manager.load_token(test_email_2)
    print(f"Loaded token for {test_email_2}: {loaded_token_2}")
    assert loaded_token_2 == test_token_2
    last_email = manager.get_last_saved_token_email()
    print(f"Last saved token email: {last_email}")
    assert last_email == test_email_2


    print("\n--- Test clearing all again after multiple users ---")
    manager.clear_all_keychain_entries() # This will only clear token for last_email (another@example.com)
                                        # and generic GUI keys.
                                        # Tokens for other emails (test@example.com) would remain.

    # To clear ALL tokens, we would need to know all emails for which tokens were saved,
    # or change the token storage strategy (e.g., a single key storing a dict of email:token).
    # For now, clear_all_keychain_entries is limited to last known user's token and general GUI keys.
    # A more robust clear_all would require a list of all user emails ever used for tokens,
    # which isn't currently stored by this manager.

    # Let's refine clear_all_keychain_entries or add a specific method if we need to wipe all tokens
    # without knowing all emails. However, the current approach is usually sufficient as keyring
    # access is typically scoped by the OS user.

    # Re-saving and clearing specifically for the first user to ensure it's gone
    manager.save_token(test_email, test_token) # Resave first user's token
    manager.clear_token(test_email) # Clear first user's token specifically
    loaded_token_after_specific_clear = manager.load_token(test_email)
    print(f"Token for {test_email} after specific clear: {loaded_token_after_specific_clear}")
    assert loaded_token_after_specific_clear is None

    manager.clear_token(test_email_2) # Clear second user's token specifically
    loaded_token_2_after_specific_clear = manager.load_token(test_email_2)
    print(f"Token for {test_email_2} after specific clear: {loaded_token_2_after_specific_clear}")
    assert loaded_token_2_after_specific_clear is None

    print("\nAll local tests passed.")
