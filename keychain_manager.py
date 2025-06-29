import keyring
import json

# --- Keyring Constants ---
# Use a single service name for both CLI and GUI to unify keychain access.
SHARED_KEYRING_SERVICE_NAME = "BambuStudioHelper"
KEYCHAIN_DATA_ACCOUNT_NAME = "BambuStudioUserData" # Single account name for the JSON blob


class KeychainManager:
    def __init__(self, service_name=SHARED_KEYRING_SERVICE_NAME):
        self.service_name = service_name

    def _load_keychain_data(self) -> dict:
        """Loads and deserializes data from the keychain."""
        try:
            json_blob = keyring.get_password(self.service_name, KEYCHAIN_DATA_ACCOUNT_NAME)
            if json_blob:
                return json.loads(json_blob)
        except Exception as e: # Includes keyring errors and json.JSONDecodeError
            print(f"Error loading or deserializing keychain data: {e}")
        return {}

    def _save_keychain_data(self, data: dict):
        """Serializes and saves data to the keychain."""
        try:
            json_blob = json.dumps(data)
            keyring.set_password(self.service_name, KEYCHAIN_DATA_ACCOUNT_NAME, json_blob)
        except Exception as e: # Includes keyring errors
            print(f"Error serializing or saving keychain data: {e}")

    # --- Token Management (CLI and GUI) ---
    def save_token(self, email: str, token: str):
        """Saves an access token, associating it with an email."""
        if not email or not token:
            # print("Email and token are required to save.") # Or raise error
            return
        try:
            data = self._load_keychain_data()
            data.setdefault('tokens', {})[email.lower()] = token
            data['last_token_user_email'] = email.lower()
            self._save_keychain_data(data)
            # print(f"Token for {email} saved to keychain.")
        except Exception as e:
            print(f"Error saving token to keychain: {e}") # Consider logging or specific error handling

    def load_token(self, email: str) -> str | None:
        """Loads an access token associated with an email."""
        if not email:
            return None
        try:
            data = self._load_keychain_data()
            return data.get('tokens', {}).get(email.lower())
        except Exception as e:
            print(f"Error loading token from keychain: {e}")
            return None

    def clear_token(self, email: str):
        """Clears an access token associated with an email."""
        if not email:
            return
        try:
            data = self._load_keychain_data()
            email_lower = email.lower()
            if 'tokens' in data and email_lower in data['tokens']:
                data['tokens'].pop(email_lower)
                # print(f"Token for {email} cleared from keychain.")

            if data.get('last_token_user_email') == email_lower:
                data.pop('last_token_user_email', None)

            self._save_keychain_data(data)
        except Exception as e:
            print(f"Error clearing token from keychain: {e}")

    def get_last_saved_token_email(self) -> str | None:
        """Gets the email of the user whose token was last saved."""
        try:
            data = self._load_keychain_data()
            return data.get('last_token_user_email')
        except Exception as e:
            print(f"Error retrieving last token user email: {e}")
            return None

    # --- GUI Credential Management ---
    def save_gui_credentials(self, email: str | None, password: str | None, serial: str | None):
        """Saves GUI credentials (email, password, serial). Intended for 'Save Credentials' feature."""
        try:
            data = self._load_keychain_data()
            gui_creds = data.setdefault('gui_credentials', {})

            if email is not None:
                gui_creds['email'] = email
            if password is not None:
                gui_creds['password'] = password
            if serial is not None:
                gui_creds['serial'] = serial

            self._save_keychain_data(data)
            # print("GUI credentials saved to keychain.")
        except Exception as e:
            print(f"Error saving GUI credentials to keychain: {e}")

    def load_gui_credentials(self) -> dict:
        """Loads GUI credentials (email, password, serial)."""
        try:
            data = self._load_keychain_data()
            return data.get('gui_credentials', {"email": None, "password": None, "serial": None})
        except Exception as e:
            print(f"Error loading GUI credentials from keychain: {e}")
            return {"email": None, "password": None, "serial": None}

    def clear_gui_credentials(self):
        """Clears all saved GUI credentials."""
        try:
            data = self._load_keychain_data()
            if 'gui_credentials' in data:
                data.pop('gui_credentials')
                self._save_keychain_data(data)
            # print("GUI credentials cleared from keychain.")
        except Exception as e:
            print(f"Error clearing GUI credentials from keychain: {e}")

    def clear_all_for_email(self, email: str):
        """Clears token and GUI credentials associated with a specific email."""
        email_lower = email.lower() # Ensure consistent casing for comparison
        self.clear_token(email_lower) # clear_token already handles lowercasing internally for its keys

        data = self._load_keychain_data()
        gui_creds = data.get('gui_credentials')
        if gui_creds and gui_creds.get("email") and gui_creds.get("email").lower() == email_lower:
            if 'gui_credentials' in data: # Check again before pop, though clear_gui_credentials would do it
                data.pop('gui_credentials')
                self._save_keychain_data(data) # Save after modification
                # Or call self.clear_gui_credentials() which does load/pop/save

    def clear_all_keychain_entries(self):
        """
        Clears ALL data stored by this KeychainManager under its service_name
        by deleting the single JSON blob entry.
        """
        print(f"Attempting to clear all keychain data for service: {self.service_name} (account: {KEYCHAIN_DATA_ACCOUNT_NAME})")
        try:
            # Attempt to delete the specific item.
            # Some keyring backends might error if the item doesn't exist,
            # others might not.
            # It's also safe to just save an empty dictionary: self._save_keychain_data({})
            # but delete is more explicit for a "clear all".
            keyring.delete_password(self.service_name, KEYCHAIN_DATA_ACCOUNT_NAME)
            # print("Keychain data cleared.")
        except keyring.errors.PasswordDeleteError:
            # This can happen if the entry doesn't exist, which is fine for a clear operation.
            # print("Keychain entry not found or already deleted.")
            pass # Entry didn't exist, consider it cleared.
        except Exception as e:
            print(f"Error deleting keychain entry {KEYCHAIN_DATA_ACCOUNT_NAME} from keychain: {e}")
        # print("Finished attempting to clear all keychain entries.")

# Example Usage (optional, for testing this file directly)
if __name__ == "__main__":
    # Use a distinct service name for testing to avoid interfering with real credentials
    TEST_SERVICE_NAME = "BambuStudioHelper_Test"
    manager = KeychainManager(service_name=TEST_SERVICE_NAME)

    # --- Test Data ---
    email1 = "testuser1@example.com"
    token1 = "token_for_user1_abc123"
    email2 = "testuser2@example.com"
    token2 = "token_for_user2_xyz789"

    gui_email1 = "gui_user1@example.com"
    gui_pass1 = "gui_password1"
    gui_serial1 = "GUI_SERIAL_1"

    gui_email2 = "gui_user2@example.com" # For testing clear_all_for_email
    gui_pass2 = "gui_password2"
    gui_serial2 = "GUI_SERIAL_2"

    def run_tests():
        print(f"Using service name: {manager.service_name} and account: {KEYCHAIN_DATA_ACCOUNT_NAME}")
        print("--- Initial state: Clearing any pre-existing test data ---")
        manager.clear_all_keychain_entries()
        assert manager._load_keychain_data() == {}, "Initial data should be empty after clear"

        # Test 1: Save and Load Token
        print("\n--- Test 1: Save and Load Token ---")
        manager.save_token(email1, token1)
        assert manager.load_token(email1) == token1, "Token1 load failed"
        assert manager.get_last_saved_token_email() == email1.lower(), "Last saved email mismatch after token1"
        print("Test 1 Passed.")

        # Test 2: Save and Load Multiple Tokens
        print("\n--- Test 2: Save and Load Multiple Tokens ---")
        manager.save_token(email2, token2)
        assert manager.load_token(email2) == token2, "Token2 load failed"
        assert manager.load_token(email1) == token1, "Token1 load failed after saving token2"
        assert manager.get_last_saved_token_email() == email2.lower(), "Last saved email mismatch after token2"
        print("Test 2 Passed.")

        # Test 3: Save and Load GUI Credentials
        print("\n--- Test 3: Save and Load GUI Credentials ---")
        manager.save_gui_credentials(gui_email1, gui_pass1, gui_serial1)
        creds1 = manager.load_gui_credentials()
        assert creds1.get("email") == gui_email1, "GUI Email1 load failed"
        assert creds1.get("password") == gui_pass1, "GUI Password1 load failed"
        assert creds1.get("serial") == gui_serial1, "GUI Serial1 load failed"
        print("Test 3 Passed.")

        # Test 4: Clear Token
        print("\n--- Test 4: Clear Token ---")
        manager.save_token(email1, token1) # Ensure it's there
        manager.save_token(email2, token2) # Ensure it's there and last saved
        manager.clear_token(email1)
        assert manager.load_token(email1) is None, "Token1 should be None after clear"
        assert manager.load_token(email2) == token2, "Token2 should still exist after clearing token1"
        # last_saved_token_email was email2, clearing email1 should not change it.
        assert manager.get_last_saved_token_email() == email2.lower(), "Last saved email should be email2"
        manager.clear_token(email2) # Now clear the last saved token email
        assert manager.load_token(email2) is None, "Token2 should be None after clear"
        assert manager.get_last_saved_token_email() is None, "Last saved email should be None after clearing email2"
        print("Test 4 Passed.")

        # Test 5: Clear GUI Credentials
        print("\n--- Test 5: Clear GUI Credentials ---")
        manager.save_gui_credentials(gui_email1, gui_pass1, gui_serial1) # Save first
        assert manager.load_gui_credentials().get("email") == gui_email1, "GUI creds not saved before clear"
        manager.clear_gui_credentials()
        cleared_creds = manager.load_gui_credentials()
        assert cleared_creds.get("email") is None, "GUI Email should be None after clear"
        assert cleared_creds.get("password") is None, "GUI Password should be None after clear"
        assert cleared_creds.get("serial") is None, "GUI Serial should be None after clear"
        print("Test 5 Passed.")

        # Test 6: clear_all_for_email
        print("\n--- Test 6: clear_all_for_email ---")
        # Setup: token for email1, GUI creds for email1, token for email2
        manager.save_token(email1, token1)
        manager.save_gui_credentials(email1, gui_pass1, gui_serial1) # GUI creds for email1
        manager.save_token(email2, token2) # Different user's token

        manager.clear_all_for_email(email1)
        assert manager.load_token(email1) is None, "Token1 should be cleared by clear_all_for_email"
        cleared_gui_for_email1 = manager.load_gui_credentials() # GUI creds were for email1
        assert cleared_gui_for_email1.get("email") is None, "GUI Email1 should be cleared by clear_all_for_email"
        assert manager.load_token(email2) == token2, "Token2 should NOT be cleared by clear_all_for_email(email1)"

        # Test case: GUI creds for a different email should not be cleared
        manager.save_gui_credentials(gui_email2, gui_pass2, gui_serial2) # GUI creds for email2
        manager.save_token(email1, token1) # Re-save token1
        manager.clear_all_for_email(email1) # Clear for email1 again
        assert manager.load_token(email1) is None, "Token1 should be cleared again"
        remaining_gui_creds = manager.load_gui_credentials()
        assert remaining_gui_creds.get("email") == gui_email2, "GUI creds for email2 should remain"
        print("Test 6 Passed.")

        # Test 7: clear_all_keychain_entries
        print("\n--- Test 7: clear_all_keychain_entries ---")
        manager.save_token(email1, token1)
        manager.save_gui_credentials(gui_email1, gui_pass1, gui_serial1)
        manager.clear_all_keychain_entries()

        assert manager.load_token(email1) is None, "Token1 should be None after clear_all"
        final_cleared_creds = manager.load_gui_credentials()
        assert final_cleared_creds.get("email") is None, "GUI Email should be None after clear_all"
        assert manager.get_last_saved_token_email() is None, "Last saved email should be None after clear_all"
        assert manager._load_keychain_data() == {}, "Internal data should be empty after clear_all"
        print("Test 7 Passed.")

        # Test 8: Saving None/Empty values for GUI credentials
        print("\n--- Test 8: Saving None/Empty values for GUI credentials ---")
        manager.save_gui_credentials(email="", password="", serial=None)
        creds_empty = manager.load_gui_credentials()
        assert creds_empty.get("email") == "", "GUI email should be empty string"
        assert creds_empty.get("password") == "", "GUI password should be empty string"
        assert creds_empty.get("serial") is None, "GUI serial should be None"
        manager.clear_all_keychain_entries() # Clean up
        print("Test 8 Passed.")

        # Test 9: Operations on an empty keychain
        print("\n--- Test 9: Operations on an empty keychain ---")
        manager.clear_all_keychain_entries() # Ensure empty
        assert manager.load_token("nonexistent@example.com") is None, "Load token from empty keychain"
        assert manager.load_gui_credentials().get("email") is None, "Load GUI from empty keychain"
        assert manager.get_last_saved_token_email() is None, "Last saved email from empty keychain"
        manager.clear_token("nonexistent@example.com") # Should not error
        manager.clear_gui_credentials() # Should not error
        print("Test 9 Passed.")

        print("\n--- All refactored tests passed! ---")

    try:
        run_tests()
    finally:
        # Cleanup: ensure the test service entry is cleared after tests, regardless of success
        print("\n--- Final Cleanup: Clearing test data ---")
        manager.clear_all_keychain_entries()
        print(f"Test data for service '{TEST_SERVICE_NAME}' (account: {KEYCHAIN_DATA_ACCOUNT_NAME}) should be cleared.")
