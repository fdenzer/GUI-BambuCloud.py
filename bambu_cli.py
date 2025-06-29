import requests
import argparse
import json
import getpass
# import keyring # Replaced by KeychainManager
from keychain_manager import KeychainManager # Import the new manager

API_BASE_URL = "https://api.bambulab.com"
# KEYRING_SERVICE_NAME_CLI = "BambuStudioHelper_CLI" # Now defined in KeychainManager
# KEY_ACCESS_TOKEN = "access_token" # Now defined in KeychainManager
# KEY_USER_EMAIL = "user_email" # Now defined in KeychainManager

class BambuClient:
    def __init__(self, email, serial_number, password=None, access_token=None):
        self.email = email
        self.password = password
        self.serial_number = serial_number
        self.access_token = access_token # Allow passing token directly
        self.needs_2fa = False
        self.keychain_manager = KeychainManager() # Instantiate the manager

        if not self.access_token: # Only load from keyring if not provided directly
            self._load_token()

    def _load_token(self):
        """Loads access token from keychain_manager if available for the current email."""
        if self.email:
            try:
                token = self.keychain_manager.load_token(self.email)
                if token:
                    self.access_token = token
                    print("Loaded saved CLI session token.")
                    return True
            except Exception as e:
                print(f"Could not load CLI token from keychain: {e}")
        return False

    def _save_token(self, token):
        """Saves access token to keychain_manager for the current email."""
        if self.email and token:
            try:
                self.keychain_manager.save_token(self.email, token)
                print("Session token saved.")
            except Exception as e:
                print(f"Could not save token to keychain: {e}")

    def _clear_token(self):
        """Clears access token from keychain_manager and instance."""
        if self.email:
            try:
                self.keychain_manager.clear_token(self.email)
                self.access_token = None
                print("Saved session token cleared for current user.")
            except Exception as e:
                print(f"Error clearing token from keychain: {e}")
        else:
            # If email is not available on this client instance,
            # we might want to clear the "last used" token if that's relevant,
            # or indicate that an email is needed.
            # For now, matches previous behavior of needing an email.
            print("Email context needed to clear specific token.")


    def clear_saved_session(self):
        """Public method to clear the session for the current client's email."""
        self._clear_token()

    def _make_request(self, method, endpoint, headers=None, json_data=None, params=None):
        url = f"{API_BASE_URL}{endpoint}"
        if headers is None:
            headers = {}

        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        else: # No token, likely need to login
            pass # Login flow will handle this

        try:
            response = requests.request(method, url, headers=headers, json=json_data, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err} - {response.text}")
            if http_err.response.status_code == 401: # Unauthorized
                if "/user/login" not in endpoint: # Don't clear token if login itself failed
                    print("Authentication error (401). Token might be invalid or expired.")
                    if self.access_token: # Only clear if a token was actually used
                        self._clear_token()
                        print("Cleared invalid session token. Please login again.")
                    self.access_token = None # Ensure it's cleared from instance
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"error": "HTTP error", "message": response.text, "code": http_err.response.status_code if http_err.response else "Unknown"}
        except requests.exceptions.RequestException as req_err:
            print(f"Request exception occurred: {req_err}")
            return {"error": "Request exception", "message": str(req_err)}
        except json.JSONDecodeError as json_err: # Added specific variable for clarity
            print(f"Failed to decode JSON response: {getattr(json_err, 'doc', 'No response text available')}")
            return {"error": "JSON decode error", "message": "Invalid JSON response from server."}


    def login(self):
        # If we have a token, try a quick check to see if it's valid
        # This isn't strictly necessary if _make_request handles 401, but can give early feedback
        if self.access_token:
            # A light request to check token validity, e.g., trying to get user binds
            # If this fails with 401, _make_request will clear the token.
            # For now, we assume if a token exists, we'll try to use it directly with actual API calls.
            # If an actual API call fails, then login proceeds.
            pass


        if not self.password: # Only prompt for password if not already set (e.g. from args or previous attempt)
            self.password = getpass.getpass(f"Enter password for {self.email}: ")

        payload = {
            "account": self.email,
            "password": self.password
        }
        response = self._make_request("POST", "/v1/user-service/user/login", json_data=payload)

        if response and "accessToken" in response and response.get("accessToken"):
            self.access_token = response["accessToken"]
            self._save_token(self.access_token)
            self.needs_2fa = False
            print("Login successful.")
            return True, False # Logged in, 2FA not needed
        elif response and response.get("loginType") == "verifyCode":
            self.needs_2fa = True
            print("Login requires 2FA verification code.")
            return False, True # Not logged in, 2FA is needed
        else:
            error_message = response.get("message", "Unknown login error")
            code = response.get("code")
            if code == 401 : # Explicitly check for 401 on login attempt
                 print(f"Login failed: {error_message} (Likely incorrect credentials)")
            else:
                print(f"Login failed: {error_message}")
            self.needs_2fa = False
            return False, False

    def login_with_2fa(self, code):
        payload = {
            "account": self.email,
            "code": code
        }
        response = self._make_request("POST", "/v1/user-service/user/login", json_data=payload)

        if response and "accessToken" in response and response.get("accessToken"):
            self.access_token = response["accessToken"]
            self._save_token(self.access_token)
            self.needs_2fa = False
            print("2FA Login successful.")
            return True
        else:
            error_message = response.get("message", "Unknown 2FA login error")
            print(f"2FA Login failed: {error_message}")
            return False

    def get_device(self, serial_number_to_find):
        if not self.access_token:
            # Attempt to login if no token. This makes methods more self-sufficient.
            print("No active session. Attempting to login...")
            logged_in, needs_2fa = self.login()
            if not logged_in and needs_2fa:
                tfa_code_cli = getpass.getpass("Enter your 2FA verification code: ")
                logged_in = self.login_with_2fa(tfa_code_cli)

            if not logged_in:
                print("Authentication required. Please login first.")
                return None
            # If login was successful, self.access_token is now set.

        response = self._make_request("GET", "/v1/iot-service/api/user/bind")

        response = self._make_request("GET", "/v1/iot-service/api/user/bind")

        if response and "devices" in response:
            for device in response["devices"]:
                if device.get("dev_id") == serial_number_to_find:
                    return device
            # It's possible the response is valid but contains no devices or not the one searched for
            if not any(d.get("dev_id") == serial_number_to_find for d in response.get("devices", [])):
                 print(f"Device with serial number {serial_number_to_find} not found in bound devices.")
            return None # Return None if not found or if 'devices' key is missing/empty
        elif response and "error" in response: # Check if it's our structured error
            error_message = response.get("message", "Failed to retrieve devices")
            print(f"Error getting devices: {error_message}")
            return None
        else: # Unstructured error or unexpected response
            print(f"Failed to retrieve devices. Response: {response}")
            return None

    def get_printer_status(self, serial_number_to_find):
        if not self.access_token:
            # Attempt to login if no token.
            print("No active session. Attempting to login for printer status...")
            logged_in, needs_2fa = self.login()
            if not logged_in and needs_2fa:
                tfa_code_cli = getpass.getpass("Enter your 2FA verification code: ")
                logged_in = self.login_with_2fa(tfa_code_cli)

            if not logged_in:
                print("Authentication required to get printer status. Please login first.")
                return None
            # If login was successful, self.access_token is now set.

        # The API documentation implies /api/user/print returns status for all devices.
        # We need to filter by dev_id client-side.
        response = self._make_request("GET", "/v1/iot-service/api/user/print", params={"force": "true"})

        if response and "devices" in response:
            for device_status in response["devices"]:
                if device_status.get("dev_id") == serial_number_to_find:
                    return device_status
            print(f"Status for printer with serial number {serial_number_to_find} not found.")
            return None
        elif response and "message" in response and response["message"] != "success":
            print(f"Error getting printer status: {response['message']}")
            return None
        else:
            print(f"Failed to get printer status. Response: {response}")
            return None

def main():
    parser = argparse.ArgumentParser(description="Bambu Lab Printer Status CLI")
    parser.add_argument("email", help="Your Bambu Lab account email", nargs='?') # Optional if using --logout or if token exists
    parser.add_argument("serial_number", help="Your printer's serial number (dev_id)", nargs='?') # Optional for --logout
    parser.add_argument("-p", "--password", help="Your Bambu Lab account password (will prompt if not provided)", default=None)
    parser.add_argument("--logout", help="Clear saved session token for the specified email (or last used if email not given).", action="store_true")

    args = parser.parse_args()

    # Handle logout action first
    if args.logout:
        logout_email = args.email
        if not logout_email: # Try to get last used email for token clearing if not specified
            try:
                logout_email = keyring.get_password(KEYRING_SERVICE_NAME_CLI, KEY_USER_EMAIL)
            except Exception: # Keyring might not be available or key not set
                logout_email = None

        if logout_email:
            # We need a client instance to call clear_saved_session, even if it's temporary.
            # Serial number isn't strictly needed for logout, can pass a dummy.
            temp_client = BambuClient(email=logout_email, serial_number="dummy_serial_for_logout")
            temp_client.clear_saved_session()
            print(f"Cleared saved session for email: {logout_email}")
        else:
            # Attempt to clear token without email association (if it was saved that way, though current impl saves with email)
            # Or, if no email was ever stored, this might be a no-op or clear a generic token.
            # For the current implementation, email is expected.
            print("Email required to clear specific session, or no saved session email found.")
            # As a fallback, try to delete the generic token key if it exists (less targeted)
            try:
                if keyring.get_password(KEYRING_SERVICE_NAME_CLI, KEY_ACCESS_TOKEN):
                    keyring.delete_password(KEYRING_SERVICE_NAME_CLI, KEY_ACCESS_TOKEN)
                    print("Cleared a generic saved access token (if one existed).")
                if keyring.get_password(KEYRING_SERVICE_NAME_CLI, KEY_USER_EMAIL): # also clear the user email key
                     keyring.delete_password(KEYRING_SERVICE_NAME_CLI, KEY_USER_EMAIL)

            except Exception as e:
                print(f"Could not clear generic token: {e}")
        return # Exit after logout

    # Proceed with normal operation if not logging out
    if not args.email or not args.serial_number:
        parser.error("the following arguments are required: email, serial_number (unless using --logout)")

    client = BambuClient(email=args.email, serial_number=args.serial_number, password=args.password)

    # Try to get status. If token is valid, this will work.
    # If token is invalid or not present, get_printer_status will trigger login flow.
    # The BambuClient methods (get_printer_status, get_device) now handle their own login if no token.

    print(f"\nFetching status for printer: {args.serial_number}")
    status = client.get_printer_status(args.serial_number)

    if client.access_token and status: # Check if we have a token AND got status
        # Status already printed by get_printer_status if successful (or errors by it too)
        # We just need to format and print the details here as before.

        # Optionally, first verify the device exists and get its name
        # device_info = client.get_device(args.serial_number)
        # if device_info:
        #     print(f"Device Name: {device_info.get('name', 'N/A')}")
        #     print(f"Device Online: {device_info.get('online', 'N/A')}")
        # else:
        #     print(f"Could not retrieve details for device {args.serial_number}.")
        #     return

        status = client.get_printer_status(args.serial_number)
        if status:
            print("\n--- Printer Status ---")
            print(f"  Device ID: {status.get('dev_id')}")
            print(f"  Device Name: {status.get('dev_name')}")
            print(f"  Online: {status.get('dev_online')}")
            print(f"  Task Name: {status.get('task_name', 'N/A')}")
            print(f"  Task Status: {status.get('task_status', 'N/A')}")
            print(f"  Progress: {status.get('progress', 'N/A')}")
            print(f"  Start Time: {status.get('start_time', 'N/A')}")
            print(f"  Prediction (s): {status.get('prediction', 'N/A')}")
            # print(json.dumps(status, indent=2)) # For full details
        else:
            print("Could not retrieve printer status.")
    else:
        print("Exiting due to login failure.")

if __name__ == "__main__":
    main()
