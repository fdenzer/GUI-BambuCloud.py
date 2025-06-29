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

import logging
import datetime
import traceback

# --- Setup API Logger ---
# Create a logger
api_logger = logging.getLogger('bambu_api')
api_logger.setLevel(logging.DEBUG) # Log all levels from DEBUG upwards

# Create a file handler for API logs
log_filename = f"bambu_api_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
file_handler = logging.FileHandler(log_filename)
file_handler.setLevel(logging.DEBUG)

# Create a logging format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handlers to the logger
if not api_logger.hasHandlers(): # Avoid adding multiple handlers if module is reloaded
    api_logger.addHandler(file_handler)
# --- End API Logger Setup ---

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
                    api_logger.info(f"Loaded saved CLI session token for email: {self.email}.")
                    print("Loaded saved CLI session token.")
                    return True
            except Exception as e:
                api_logger.error(f"Could not load CLI token from keychain for {self.email}: {e}\n{traceback.format_exc()}")
                print(f"Could not load CLI token from keychain: {e}")
        return False

    def _save_token(self, token):
        """Saves access token to keychain_manager for the current email."""
        if self.email and token:
            try:
                self.keychain_manager.save_token(self.email, token)
                api_logger.info(f"Session token saved for email: {self.email}.")
                print("Session token saved.")
            except Exception as e:
                api_logger.error(f"Could not save token to keychain for {self.email}: {e}\n{traceback.format_exc()}")
                print(f"Could not save token to keychain: {e}")

    def _clear_token(self):
        """Clears access token from keychain_manager and instance."""
        if self.email:
            try:
                self.keychain_manager.clear_token(self.email)
                self.access_token = None
                api_logger.info(f"Saved session token cleared for email: {self.email}.")
                print("Saved session token cleared for current user.")
            except Exception as e:
                api_logger.error(f"Error clearing token from keychain for {self.email}: {e}\n{traceback.format_exc()}")
                print(f"Error clearing token from keychain: {e}")
        else:
            api_logger.warning("Attempted to clear token, but no email context in client.")
            print("Email context needed to clear specific token.")


    def clear_saved_session(self):
        """Public method to clear the session for the current client's email."""
        self._clear_token()

    def _make_request(self, method, endpoint, headers=None, json_data=None, params=None):
        url = f"{API_BASE_URL}{endpoint}"
        request_headers = {} if headers is None else headers.copy() # Use a copy

        log_headers = request_headers.copy()
        if 'Authorization' in log_headers:
            log_headers['Authorization'] = 'Bearer [REDACTED]'


        api_logger.debug(f"Request: {method} {url}")
        api_logger.debug(f"Params: {params}")
        api_logger.debug(f"Headers: {log_headers}")
        if json_data:
            api_logger.debug(f"JSON Body: {json.dumps(json_data)}")


        if self.access_token:
            request_headers['Authorization'] = f'Bearer {self.access_token}'
        # else: No token, likely need to login - login flow will handle this

        response_content_for_return = None # Store what we will return

        try:
            response = requests.request(method, url, headers=request_headers, json=json_data, params=params, timeout=10) # Added timeout
            api_logger.debug(f"Response Status Code: {response.status_code}")
            api_logger.debug(f"Response Headers: {dict(response.headers)}")
            try:
                response_json = response.json()
                api_logger.debug(f"Response JSON Body: {json.dumps(response_json, indent=2)}")
                response_content_for_return = response_json
            except json.JSONDecodeError:
                api_logger.warning(f"Response is not valid JSON. Raw text: {response.text[:500]}...") # Log first 500 chars
                response_content_for_return = {"error": "JSON decode error", "message": response.text, "code": response.status_code}

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        except requests.exceptions.HTTPError as http_err:
            api_logger.error(f"HTTP error occurred: {http_err} - Detail: {http_err.response.text if http_err.response else 'No response body'}\n{traceback.format_exc()}")
            print(f"HTTP error occurred: {http_err} - {http_err.response.text if http_err.response else 'No response text'}")

            # Try to parse response.json() even on HTTPError, as it might contain useful error details from API
            # If response_content_for_return was already set (e.g. from JSONDecodeError block), use it.
            if response_content_for_return is None and http_err.response is not None:
                try:
                    response_content_for_return = http_err.response.json()
                except json.JSONDecodeError:
                    response_content_for_return = {"error": "HTTP error with non-JSON response", "message": http_err.response.text, "code": http_err.response.status_code}
            elif response_content_for_return is None: # No response object on http_err (rare)
                 response_content_for_return = {"error": "HTTP error", "message": str(http_err), "code": "Unknown"}


            if http_err.response is not None and http_err.response.status_code == 401: # Unauthorized
                if "/user/login" not in endpoint: # Don't clear token if login itself failed
                    api_logger.warning("Authentication error (401). Token might be invalid or expired.")
                    print("Authentication error (401). Token might be invalid or expired.")
                    if self.access_token: # Only clear if a token was actually used
                        self._clear_token() # This already logs and prints
                        print("Cleared invalid session token. Please login again.")
                    self.access_token = None # Ensure it's cleared from instance

        except requests.exceptions.RequestException as req_err: # Covers ConnectionError, Timeout, TooManyRedirects, etc.
            api_logger.error(f"Request exception occurred: {req_err}\n{traceback.format_exc()}")
            print(f"Request exception occurred: {req_err}")
            response_content_for_return = {"error": "Request exception", "message": str(req_err)}

        # The initial try block for response.json() covers this, but if raise_for_status() happens first
        # and we didn't get to parse JSON, this is a fallback.
        # However, the logic above now tries to parse JSON from http_err.response if possible.
        # This specific except block for JSONDecodeError might be redundant if all paths set response_content_for_return.
        # For safety, let's keep a general catch.
        except json.JSONDecodeError as json_err_final: # Should be caught by inner try/except now
            api_logger.error(f"Failed to decode JSON response (outer catch): {getattr(json_err_final, 'doc', 'No response text available')}\n{traceback.format_exc()}")
            print(f"Failed to decode JSON response: {getattr(json_err_final, 'doc', 'No response text available')}")
            if response_content_for_return is None: # If not already set by inner JSON parsing attempt
                 response_content_for_return = {"error": "JSON decode error", "message": "Invalid JSON response from server."}

        return response_content_for_return


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
        device_initial_status = None

        if response and "devices" in response:
            for dev_status in response["devices"]:
                if dev_status.get("dev_id") == serial_number_to_find:
                    device_initial_status = dev_status
                    break
            if not device_initial_status:
                print(f"Device with serial number {serial_number_to_find} not found in /api/user/print response.")
                return None
        elif response and "error" in response: # Handle structured error from _make_request
            error_message = response.get("message", "Failed to retrieve initial device status")
            print(f"Error getting initial device status: {error_message}")
            return None
        else:
            print(f"Failed to get initial printer status or unexpected response: {response}")
            return None

        # If device is offline or no task details are expected from it directly, return initial status
        if not device_initial_status.get("dev_online") or not device_initial_status.get("dev_id"):
            return device_initial_status

        # Device is online, try to get detailed task status from /my/tasks
        print(f"Device {serial_number_to_find} is online. Fetching detailed tasks...")
        tasks_response = self._make_request("GET", "/v1/user-service/my/tasks", params={"deviceId": serial_number_to_find})

        if tasks_response and "hits" in tasks_response:
            active_task_details = None
            for task in tasks_response["hits"]:
                # Assuming 'status: 2' means currently printing as per Gist observation.
                # The Gist also mentions: "if endTime is within a minute of startTime, that means the file is currently printing"
                # We'll primarily rely on a status indicator if available, or startTime/endTime logic.
                # For now, let's assume a status field like `task_status` from the device or a specific `status` from the task.
                # The Gist shows task["status"] == 2. Let's use that.
                # Also ensure task["deviceId"] matches our device.
                if task.get("deviceId") == serial_number_to_find and task.get("status") == 2: # 2 seems to be 'printing'
                    # Check the startTime/endTime logic as a fallback or confirmation
                    # The Gist says: "if endTime is within a minute of startTime, that means the file is currently printing"
                    # This seems more like a way to identify tasks that *just started* or are *about to start* if 'status' isn't definitive.
                    # Let's prioritize a direct status field. If task.get("status") == 2 is reliable, we use it.
                    active_task_details = task
                    break # Found the active task

            if active_task_details:
                print(f"Found active task: {active_task_details.get('title', 'N/A')}")
                # Augment the initial device status with details from the active task
                # The GUI expects 'task_name', 'task_status', 'progress', 'start_time', 'prediction'
                device_initial_status['task_name'] = active_task_details.get('title', 'N/A')
                # The task's 'status' field (e.g., 2) might be numeric. The GUI might expect a string.
                # For now, let's pass it as is and see how the GUI handles it or adjust later.
                # It's better to map it to a human-readable string if possible.
                # Based on user output: "Task Status: N/A" but printer is printing.
                # The API might use different terms. Gist for /api/user/print shows "task_status": null.
                # Gist for /my/tasks shows "status": 2.
                # Let's try to map status 2 to something like "Printing"
                task_status_map = {
                    0: "Unknown", # Placeholder
                    1: "Preparing", # Placeholder
                    2: "Printing", # Based on Gist observation for active task
                    3: "Paused", # Placeholder
                    4: "Completed", # Placeholder
                    5: "Failed", # Placeholder
                }
                device_initial_status['task_status'] = task_status_map.get(active_task_details.get('status'), 'N/A')

                device_initial_status['start_time'] = active_task_details.get('startTime', 'N/A')
                # 'costTime' from /my/tasks is total print duration in seconds. This is our 'prediction'.
                device_initial_status['prediction'] = active_task_details.get('costTime', 'N/A')

                # Calculate progress if possible
                # Progress = ((current_time - start_time_seconds) / total_duration_seconds) * 100
                # This will be handled in the GUI as it has access to current time and can format.
                # For now, we can pass the raw values needed for calculation.
                # The GUI currently expects a 'progress' field. If not directly available, we might need to calculate it here
                # or ensure the GUI can derive it. The Gist for /api/user/print has "progress": null.
                # The Gist for /my/tasks does not have a 'progress' field.
                # Let's set it to 'N/A' here and let GUI handle calculation if it can.
                device_initial_status['progress'] = 'N/A' # Or calculate if feasible here.

                return device_initial_status
            else:
                print(f"No currently active task found for {serial_number_to_find} in /my/tasks.")
                # Return the initial status, which will show N/A for task details
                return device_initial_status
        elif tasks_response and "error" in tasks_response:
            error_message = tasks_response.get("message", "Failed to retrieve tasks")
            print(f"Error fetching tasks for {serial_number_to_find}: {error_message}")
            # Fallback to initial status; it's better than returning None if the device info is available
            return device_initial_status
        else:
            print(f"Failed to retrieve tasks or unexpected response for {serial_number_to_find}: {tasks_response}")
            return device_initial_status

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
