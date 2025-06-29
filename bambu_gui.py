import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading # For running backend tasks without freezing UI
from bambu_cli import BambuClient # Assuming bambu_cli.py is in the same directory or PYTHONPATH
import os
from dotenv import load_dotenv
# import keyring # Replaced by KeychainManager
from keychain_manager import KeychainManager # Import the new manager

# --- Keyring Constants ---
# KEYRING_SERVICE_NAME = "BambuStudioHelper_GUI" # Now handled by KeychainManager
# KEY_EMAIL = "user_email" # Now handled by KeychainManager
# KEY_SERIAL = "printer_serial" # Now handled by KeychainManager
# KEY_PASSWORD = "user_password" # Now handled by KeychainManager
# KEY_ACCESS_TOKEN_GUI = "gui_access_token" # Now handled by KeychainManager


class BambuStatusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bambu Lab Printer Status")
        self.root.geometry("500x700") # Increased height for two text areas

        load_dotenv()
        self.keychain_manager = KeychainManager() # Instantiate the manager
        self.client = None
        self.login_requires_2fa = False
        self.active_session_loaded_from_keyring = False # Track if current session is from keyring

        # --- In-memory cache for credentials (still useful for UI state) ---
        self.cached_email = None
        self.cached_serial = None
        self.cached_password = None # Password from "save credentials"
        self.cached_token = None # Token loaded for the session
        self.cached_token_email = None # Email associated with the loaded token

        # This flag is less about "keyring access attempted" and more about "initial load done"
        self.initial_keychain_load_done = False
        # --- End of cache variables ---

        # Style
        style = ttk.Style()
        style.theme_use('clam') # 'clam', 'alt', 'default', 'classic'

        # Main frame
        main_frame = ttk.Frame(root, padding="10 10 10 10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # --- Credentials and Serial ---
        creds_frame = ttk.LabelFrame(main_frame, text="Credentials & Printer", padding="10 10 10 10")
        creds_frame.pack(fill=tk.X, pady=5)

        ttk.Label(creds_frame, text="Email:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.email_entry = ttk.Entry(creds_frame, width=30)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        # self.email_entry.insert(0, os.getenv("username", "")) # Population handled by _populate_fields_from_keyring


        ttk.Label(creds_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(creds_frame, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        # self.password_entry.insert(0, os.getenv("password", "")) # Population handled by _populate_fields_from_keyring

        ttk.Label(creds_frame, text="Serial Number:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.serial_entry = ttk.Entry(creds_frame, width=30)
        self.serial_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        # self.serial_entry.insert(0, os.getenv("printer_sn", "")) # Population handled by _populate_fields_from_keyring

        self.save_creds_var = tk.BooleanVar()
        self.save_creds_checkbox = ttk.Checkbutton(creds_frame, text="Save Credentials Securely", variable=self.save_creds_var, command=self.on_save_creds_toggled)
        self.save_creds_checkbox.grid(row=3, column=0, columnspan=2, pady=5, sticky="w")

        # --- 2FA Frame (initially hidden) ---
        self.tfa_frame = ttk.LabelFrame(main_frame, text="Two-Factor Authentication", padding="10 10 10 10")
        # self.tfa_frame.pack(fill=tk.X, pady=5) # Packed later if needed

        ttk.Label(self.tfa_frame, text="2FA Code:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.tfa_entry = ttk.Entry(self.tfa_frame, width=20)
        self.tfa_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.tfa_frame.grid_columnconfigure(1, weight=1)


        # --- Action Button ---
        self.action_button = ttk.Button(main_frame, text="Get Printer Status", command=self.handle_action)
        self.action_button.pack(pady=10, fill=tk.X)

        # --- Log Display ---
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10 10 10 10")
        log_frame.pack(expand=True, fill=tk.BOTH, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8, state=tk.DISABLED)
        self.log_text.pack(expand=True, fill=tk.BOTH)

        # --- Status Display ---
        status_display_frame = ttk.LabelFrame(main_frame, text="Printer Status", padding="10 10 10 10")
        status_display_frame.pack(expand=True, fill=tk.BOTH, pady=5)

        self.status_display_text = scrolledtext.ScrolledText(status_display_frame, wrap=tk.WORD, height=7, state=tk.DISABLED)
        self.status_display_text.pack(expand=True, fill=tk.BOTH)

        creds_frame.grid_columnconfigure(1, weight=1)

        # Initial attempt to load session and populate fields
        self._try_load_session()

    # Removed old _set_status method

    def _set_log_message(self, message, append=True, is_error=False):
        self.log_text.config(state=tk.NORMAL)
        if not append:
            self.log_text.delete(1.0, tk.END)

        if is_error:
            self.log_text.insert(tk.END, message + "\n", "error")
            self.log_text.tag_config("error", foreground="red")
        else:
            self.log_text.insert(tk.END, message + "\n")

        self.log_text.see(tk.END)  # Scroll to the end
        self.log_text.config(state=tk.DISABLED)

    def _set_status_display(self, message, is_error=False):
        self.status_display_text.config(state=tk.NORMAL)
        self.status_display_text.delete(1.0, tk.END) # Always clear before new status

        if is_error: # Though typically printer status won't be an "error" in this text area, good to have
            self.status_display_text.insert(tk.END, message + "\n", "error")
            self.status_display_text.tag_config("error", foreground="red")
        else:
            self.status_display_text.insert(tk.END, message + "\n")

        self.status_display_text.see(tk.END) # Scroll to the end
        self.status_display_text.config(state=tk.DISABLED)

    def _clear_status_display(self):
        self.status_display_text.config(state=tk.NORMAL)
        self.status_display_text.delete(1.0, tk.END)
        self.status_display_text.config(state=tk.DISABLED)

    def handle_action(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        serial = self.serial_entry.get()
        tfa_code = self.tfa_entry.get()

        if not email or not serial:
            messagebox.showerror("Input Error", "Email and Serial Number are required.")
            return

        # Disable button during processing
        self.action_button.config(state=tk.DISABLED)
        self._set_log_message("Processing...", append=False) # Clear log and show processing
        self._clear_status_display() # Clear previous status

        # Run backend logic in a separate thread to avoid freezing the UI
        thread = threading.Thread(target=self._perform_action_thread, args=(email, password, serial, tfa_code))
        thread.daemon = True # Allows main program to exit even if threads are running
        thread.start()

    def _perform_action_thread(self, email, password, serial, tfa_code):
        try:
            if not self.client or self.client.email != email: # New client or different email
                self.client = BambuClient(email=email, serial_number=serial, password=password if password else None)
                self.login_requires_2fa = False # Reset 2FA flag for new client/login attempt

            if not self.client.access_token: # Not logged in yet
                if self.login_requires_2fa: # This is a 2FA code submission attempt
                    if not tfa_code:
                        self.root.after(0, lambda: self._set_log_message("2FA code is required. Please enter it and try again.", is_error=True, append=True))
                        self.root.after(0, self._update_ui_for_2fa_input) # Ensure UI is set for 2FA
                        return

                    self.root.after(0, lambda: self._set_log_message("Attempting login with 2FA code...", append=True))
                    logged_in = self.client.login_with_2fa(tfa_code)
                    if logged_in:
                        self.login_requires_2fa = False # Clear flag after successful 2FA
                        self.root.after(0, self._update_ui_after_login)
                        self.root.after(0, lambda: self._set_log_message("2FA Login successful.", append=True))
                    else:
                        self.root.after(0, lambda: self._set_log_message("2FA Login failed. Check code or credentials.", is_error=True, append=True))
                        # Keep UI in 2FA mode for retry
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return
                else: # Initial login attempt (with password)
                    if not password: # Prompt if password wasn't entered (though CLI does this, GUI should ensure it's there or fail)
                         self.root.after(0, lambda: self._set_log_message("Password is required for initial login.", is_error=True, append=True))
                         return

                    self.root.after(0, lambda: self._set_log_message("Attempting login...", append=True))
                    logged_in, needs_2fa_flag = self.client.login()

                    if logged_in:
                        self.login_requires_2fa = False
                        self.root.after(0, self._update_ui_after_login)
                        self.root.after(0, lambda: self._set_log_message("Login successful.", append=True))
                    elif needs_2fa_flag:
                        self.login_requires_2fa = True
                        self.root.after(0, lambda: self._set_log_message("Login requires 2FA. Please enter the code below and click 'Login with 2FA Code'.", append=True))
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return # Stop here, wait for user to input 2FA and click again
                    else:
                        self.root.after(0, lambda: self._set_log_message("Login failed. Check credentials.", is_error=True, append=True))
                        return

            # If we reach here, we are logged in (either initially or after 2FA)
            if self.client.access_token:
                self.root.after(0, lambda: self._set_log_message(f"Fetching status for printer: {serial}...", append=True))
                status = self.client.get_printer_status(serial)
                if status:
                    status_pretty = "--- Printer Status ---\n" # Removed leading newline, handled by widget
                    status_pretty += f"  Device ID: {status.get('dev_id', 'N/A')}\n"
                    status_pretty += f"  Device Name: {status.get('dev_name', 'N/A')}\n"
                    status_pretty += f"  Online: {status.get('dev_online', 'N/A')}\n"
                    status_pretty += f"  Task Name: {status.get('task_name', 'N/A')}\n"
                    status_pretty += f"  Task Status: {status.get('task_status', 'N/A')}\n"
                    status_pretty += f"  Progress: {status.get('progress', 'N/A')}\n"
                    status_pretty += f"  Start Time: {status.get('start_time', 'N/A')}\n"
                    # Convert prediction (s) to target time and duration
                    prediction = status.get('prediction', None)
                    start_time = status.get('start_time', None)
                    if prediction is not None and start_time not in (None, 'N/A'):
                        import datetime
                        try:
                            # Try to parse start_time as ISO or fallback to string
                            if isinstance(start_time, str):
                                # Accepts 'YYYY-MM-DD HH:MM:SS' or ISO
                                try:
                                    st_dt = datetime.datetime.fromisoformat(start_time)
                                except Exception:
                                    st_dt = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                            else:
                                st_dt = start_time
                            target_time = st_dt + datetime.timedelta(seconds=int(prediction))
                            status_pretty += f"  Target End Time: {target_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                            # Also show duration as (dd:hh:mm:ss)
                            duration = str(datetime.timedelta(seconds=int(prediction)))
                            # Format as dd:hh:mm:ss
                            days, rest = duration.split(',') if ',' in duration else ('0 days', duration)
                            hms = rest.strip().split(':')
                            if len(hms) == 3:
                                hours, minutes, seconds = hms
                            else:
                                hours, minutes, seconds = '00', '00', '00'
                            days = days.split()[0]
                            status_pretty += f"  Remaining (dd:hh:mm:ss): {int(days):02}:{hours}:{minutes}:{seconds}\n"
                        except Exception as e:
                            status_pretty += f"  Prediction (s): {prediction} (error formatting time)\n"
                    else:
                        status_pretty += f"  Prediction (s): {status.get('prediction', 'N/A')}\n"
                    self.root.after(0, lambda s=status_pretty: self._set_status_display(s))
                else:
                    self.root.after(0, lambda: self._set_log_message(f"Could not retrieve printer status for {serial}.", is_error=True, append=True))
                    self.root.after(0, self._clear_status_display) # Clear status area on error
            else:
                # This case should ideally be caught earlier
                self.root.after(0, lambda: self._set_log_message("Not logged in. Please try logging in again.", is_error=True, append=True))

        except Exception as e:
            self.root.after(0, lambda err=str(e): self._set_log_message(f"An unexpected error occurred: {err}", is_error=True, append=True))
            self.root.after(0, self._clear_status_display) # Clear status area on error
        finally:
            # Re-enable button (must be done in the main thread)
            self.root.after(0, lambda: self.action_button.config(state=tk.NORMAL))

    def _update_ui_for_2fa_input(self):
        self.tfa_frame.pack(fill=tk.X, pady=5, before=self.action_button)
        self.action_button.config(text="Login with 2FA Code")
        self.password_entry.config(state=tk.DISABLED)
        self.email_entry.config(state=tk.DISABLED)
        self.serial_entry.config(state=tk.DISABLED)

    def _update_ui_after_login(self, session_loaded=False):
        if self.tfa_frame.winfo_ismapped():
            self.tfa_frame.pack_forget()
        self.action_button.config(text="Refresh Printer Status")

        # If session is loaded, or if saving credentials, disable password field. Otherwise, enable.
        can_edit_password = not session_loaded and not self.save_creds_var.get()
        self.password_entry.config(state=tk.NORMAL if can_edit_password else tk.DISABLED)

        self.email_entry.config(state=tk.DISABLED if session_loaded else tk.NORMAL)
        self.serial_entry.config(state=tk.DISABLED if session_loaded else tk.NORMAL)

        if session_loaded:
            self.password_entry.delete(0, tk.END) # Clear password field if session is active
            self._set_log_message("Using saved session. Ready.", append=False) # Clear log and set message
        else: # Logged in with password/2FA
            # Log message for successful login is already handled in _perform_action_thread
            # self._set_log_message("Login successful. Ready.", append=True)
            if self.save_creds_var.get(): # If saving creds, password field should be disabled post-login
                self.password_entry.config(state=tk.DISABLED)


    def _reset_ui_for_login(self):
        """ Resets UI to initial login state, e.g. after token invalidation or logout. """
        if self.tfa_frame.winfo_ismapped():
            self.tfa_frame.pack_forget()
        self.action_button.config(text="Get Printer Status")
        self.email_entry.config(state=tk.NORMAL)
        self.serial_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL) # Always allow password entry for new login

        if not self.save_creds_var.get(): # If "save" is off, clear password field
            self.password_entry.delete(0, tk.END)
        # If "save" is on, password field might contain the saved pass, leave it.

        self.client = None # Clear client
        self.login_requires_2fa = False
        self.active_session_loaded_from_keyring = False
        self._set_log_message("Please login.", append=False) # Clear log and set message
        self._clear_status_display() # Clear status area

    # --- Credential Management Methods using KeychainManager ---
    def _handle_save_creds_and_token(self, email, serial, password_to_save, token_to_save=None):
        """
        Saves GUI credentials (if 'Save Credentials' is checked) and always saves the token
        using KeychainManager. Updates local cache.
        """
        try:
            if self.save_creds_var.get():
                self.keychain_manager.save_gui_credentials(email, password_to_save, serial)
                self.cached_email = email
                self.cached_password = password_to_save # Only cache password if saved
                self.cached_serial = serial
            else:
                # If "save" is off, ensure GUI creds (especially password) are cleared from keychain
                # Email/serial might persist if they were saved independently or by a previous "save" state.
                # A more aggressive clear might be self.keychain_manager.clear_gui_credentials(),
                # but that would also remove email/serial which might be wanted for token association.
                # For now, just ensure password is not saved if box is unchecked.
                gui_creds = self.keychain_manager.load_gui_credentials()
                self.keychain_manager.save_gui_credentials(
                    email=gui_creds.get("email"), # Keep existing email
                    password=None, # Explicitly clear password
                    serial=gui_creds.get("serial") # Keep existing serial
                )
                self.cached_password = None # Clear cached password

            if token_to_save and email:
                self.keychain_manager.save_token(email, token_to_save)
                self.cached_token = token_to_save
                self.cached_token_email = email
            return True
        except Exception as e:
            self.root.after(0, lambda: self._set_log_message(f"Error saving data via KeychainManager: {e}", is_error=True, append=True))
            return False

    def _load_data_from_keychain(self):
        """
        Loads GUI credentials and the last used token using KeychainManager.
        Populates the cache.
        """
        if self.initial_keychain_load_done: # Only load from keychain once per session unless forced
            return {
                "email": self.cached_email,
                "serial": self.cached_serial,
                "password": self.cached_password,
                "token": self.cached_token,
                "token_email": self.cached_token_email
            }

        try:
            gui_creds = self.keychain_manager.load_gui_credentials()
            loaded_email = gui_creds.get("email")
            loaded_password = gui_creds.get("password")
            loaded_serial = gui_creds.get("serial")

            # Attempt to load a token. Try last known token user first, then GUI email.
            token_email_to_try = self.keychain_manager.get_last_saved_token_email() or loaded_email
            loaded_token = None
            if token_email_to_try:
                loaded_token = self.keychain_manager.load_token(token_email_to_try)

            # Update cache
            self.cached_email = loaded_email
            self.cached_password = loaded_password # Will be None if not saved
            self.cached_serial = loaded_serial
            self.cached_token = loaded_token
            self.cached_token_email = token_email_to_try if loaded_token else None

            self.initial_keychain_load_done = True

            return {
                "email": self.cached_email,
                "serial": self.cached_serial,
                "password": self.cached_password,
                "token": self.cached_token,
                "token_email": self.cached_token_email
            }
        except Exception as e:
            self.root.after(0, lambda: self._set_log_message(f"Error loading data via KeychainManager: {e}", is_error=True, append=True))
            self.initial_keychain_load_done = True # Mark as done even on error to avoid loops
            # Clear cache on error
            self.cached_email = None
            self.cached_serial = None
            self.cached_password = None
            self.cached_token = None
            self.cached_token_email = None
            return {"email": None, "serial": None, "password": None, "token": None, "token_email": None}

    def _handle_clear_creds_and_token(self):
        """
        Clears GUI credentials and the current user's token (if email known)
        using KeychainManager. Resets relevant parts of the cache.
        """
        try:
            current_email_in_field = self.email_entry.get() # Email currently in the UI field

            # Clear GUI credentials (general, not tied to a specific email by KeychainManager's design)
            self.keychain_manager.clear_gui_credentials()

            # Clear token for the email that was active or last known for a token
            email_to_clear_token_for = self.cached_token_email or current_email_in_field
            if email_to_clear_token_for:
                self.keychain_manager.clear_token(email_to_clear_token_for)

            if self.client: self.client.access_token = None
            self.active_session_loaded_from_keyring = False

            # Reset cache related to saved state
            self.cached_email = None # GUI creds are cleared, so this should be too
            self.cached_serial = None # ditto
            self.cached_password = None # ditto
            self.cached_token = None
            self.cached_token_email = None
            # self.initial_keychain_load_done = False # Allow re-load on next app start, not during this action

            return True
        except Exception as e:
            self.root.after(0, lambda: self._set_log_message(f"Error deleting data via KeychainManager: {e}", is_error=True, append=True))
            return False

    def _try_load_session(self):
        """Populates UI fields based on data loaded from KeychainManager."""
        data = self._load_data_from_keychain()

        # Use token_email for client if available, otherwise GUI email
        # This prioritizes the email associated with an active session token.
        email_for_client = data.get("token_email") or data.get("email")
        serial_for_client = data.get("serial")
        token_for_client = data.get("token")
        password_from_keychain = data.get("password") # This is the saved GUI password

        populated_from_keychain = False
        if data.get("email"): # GUI saved email
            self.email_entry.delete(0, tk.END); self.email_entry.insert(0, data.get("email"))
            populated_from_keychain = True
        if data.get("serial"): # GUI saved serial
            self.serial_entry.delete(0, tk.END); self.serial_entry.insert(0, data.get("serial"))
            populated_from_keychain = True

        # Set "Save Credentials" checkbox and password field based on loaded GUI password
        if password_from_keychain and data.get("email"): # Password was saved for this email
            self.save_creds_var.set(True)
            self.password_entry.delete(0, tk.END); self.password_entry.insert(0, password_from_keychain)
        else:
            self.save_creds_var.set(False)
            self.password_entry.delete(0, tk.END)

        if not populated_from_keychain: # Fallback to .env if nothing from keychain for email/serial
            env_email = os.getenv("username", "")
            env_serial = os.getenv("printer_sn", "")
            if not self.email_entry.get() and env_email : self.email_entry.insert(0, env_email)
            if not self.serial_entry.get() and env_serial : self.serial_entry.insert(0, env_serial)

        if token_for_client and email_for_client:
            # If the email field was populated by GUI creds and differs from token_email,
            # update the email field to match the token's email for consistency.
            if self.email_entry.get() != email_for_client:
                self.email_entry.delete(0, tk.END); self.email_entry.insert(0, email_for_client)

            self.client = BambuClient(email=email_for_client,
                                      serial_number=serial_for_client if serial_for_client else "",
                                      access_token=token_for_client)
            self.active_session_loaded_from_keyring = True
            self._update_ui_after_login(session_loaded=True)
            self._set_log_message(f"Verifying saved session for {email_for_client}...", append=False)
            self._clear_status_display()
            self.handle_action() # Auto-refresh
        else:
            self._reset_ui_for_login()
            # If save_creds_var is true (meaning password was loaded) ensure field is editable initially
            if self.save_creds_var.get() and self.password_entry.get():
                self.password_entry.config(state=tk.NORMAL)
            elif not self.save_creds_var.get():
                self.password_entry.delete(0, tk.END)


    def on_save_creds_toggled(self):
        email = self.email_entry.get()
        serial = self.serial_entry.get()
        # Password from field is only relevant if we are *saving* it now.
        # If unchecking, we clear based on what's in keychain.

        if self.save_creds_var.get(): # Box just got CHECKED
            # This action primarily signals intent. Actual saving of password happens on successful login.
            # We can save email/serial now if they are not empty.
            # KeychainManager().save_gui_credentials handles this.
            # No direct keychain interaction here needed, _handle_save_creds_and_token will do it.
            self.keychain_manager.save_gui_credentials(email=email or None, # Save if exists
                                                       password=None, # Don't save password yet
                                                       serial=serial or None) # Save if exists
            if email: self.cached_email = email
            if serial: self.cached_serial = serial

            self.password_entry.config(state=tk.DISABLED if self.active_session_loaded_from_keyring else tk.NORMAL)
            self._set_log_message("Credentials (email/serial updated if entered, password will be stored on next successful login).", append=True)
        else: # Box just got UNCHECKED
            # Clear saved GUI credentials (especially password) and any active token for the current user.
            if self._handle_clear_creds_and_token():
                self._set_log_message("Saved credentials and current user session cleared.", append=True)
            self._reset_ui_for_login() # Full UI reset

    def _perform_action_thread(self, email, password, serial, tfa_code):
        try:
            current_token_email = self.cached_token_email # Email associated with any loaded token
            current_token = self.cached_token

            # --- Client Initialization & Token Validation ---
            # Condition for new client:
            # 1. No client exists OR
            # 2. Email in form differs from client's current email OR
            # 3. A session was supposedly loaded, but the client's token is now gone (e.g., invalidated by BambuClient)
            if not self.client or \
               self.client.email != email or \
               (self.active_session_loaded_from_keyring and not self.client.access_token):

                if self.active_session_loaded_from_keyring and not self.client.access_token :
                    # Loaded session token was invalidated by BambuClient. Clear it from keychain.
                    self.root.after(0, lambda: self._set_log_message("Saved session was invalid. Please login.", is_error=True, append=True))
                    if current_token_email: # Ensure we have an email to target for token clearing
                        self.keychain_manager.clear_token(current_token_email)
                    # Also clear general GUI credentials as a precaution or if they were tied to this failed session concept
                    # self.keychain_manager.clear_gui_credentials() # This might be too broad if user has other GUI settings
                    self.active_session_loaded_from_keyring = False
                    self.cached_token = None # Clear cached token
                    self.cached_token_email = None
                    # UI should be reset for login by _reset_ui_for_login called later if login fails

                # Initialize client:
                # If there's a cached token for *this specific email* and it matches current_token, use it.
                # This handles the case where the app starts, loads a token, and user hits "refresh".
                token_to_init_client = None
                if email == current_token_email and current_token:
                    token_to_init_client = current_token

                self.client = BambuClient(email=email, serial_number=serial, password=password, access_token=token_to_init_client)
                self.login_requires_2fa = False # Reset 2FA for new client/attempt.

            # --- Login (if no valid token on client) ---
            if not self.client.access_token:
                self.active_session_loaded_from_keyring = False # If we are here, any prior loaded session is not being used

                if self.login_requires_2fa:
                    if not tfa_code:
                        self.root.after(0, lambda: self._set_log_message("2FA code is required.", is_error=True, append=True))
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return
                    self.root.after(0, lambda: self._set_log_message("Attempting 2FA login...", append=True))
                    logged_in = self.client.login_with_2fa(tfa_code)
                    if logged_in:
                        self.login_requires_2fa = False
                        # Save token and potentially credentials (password if "save" is checked)
                        self._handle_save_creds_and_token(email, serial, password, self.client.access_token)
                        self.root.after(0, lambda: self._update_ui_after_login(session_loaded=False))
                    else:
                        self.root.after(0, lambda: self._set_log_message("2FA login failed.", is_error=True, append=True))
                        self.root.after(0, self._update_ui_for_2fa_input) # Stay in 2FA mode
                        return
                else: # Standard password login
                    if not self.client.password: # Password from UI field, passed to BambuClient
                        self.root.after(0, lambda: self._set_log_message("Password is required for login.", is_error=True, append=True))
                        self.root.after(0, self._reset_ui_for_login)
                        return

                    self.root.after(0, lambda: self._set_log_message("Attempting login...", append=True))
                    logged_in, needs_2fa_flag = self.client.login()
                    if logged_in:
                        self.login_requires_2fa = False
                        self._handle_save_creds_and_token(email, serial, self.client.password, self.client.access_token)
                        self.root.after(0, lambda: self._update_ui_after_login(session_loaded=False))
                        self.root.after(0, lambda: self._set_log_message("Login successful.", append=True))
                    elif needs_2fa_flag:
                        self.login_requires_2fa = True
                        self.root.after(0, lambda: self._set_log_message("Login requires 2FA. Enter code.", append=True))
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return
                    else: # Login failed (non-2FA)
                        self.root.after(0, lambda: self._set_log_message("Login failed. Check credentials.", is_error=True, append=True))
                        self.root.after(0, self._reset_ui_for_login)
                        return

            # --- API Call (if token exists on client) ---
            if self.client.access_token:
                self.root.after(0, lambda: self._set_log_message(f"Fetching status for {serial}...", append=True))
                status = self.client.get_printer_status(serial) # This uses client.access_token

                # After API call, check if token was invalidated by BambuClient (e.g. 401 error)
                if not self.client.access_token and (self.active_session_loaded_from_keyring or email == self.cached_token_email):
                    # Token became invalid. BambuClient cleared its internal token.
                    # Clear from keychain and cache.
                    self.root.after(0, lambda: self._set_log_message("Session expired or token invalid. Please login.", is_error=True, append=True))
                    email_of_invalid_token = self.cached_token_email or email # Prefer cached, fallback to current form email
                    if email_of_invalid_token:
                        self.keychain_manager.clear_token(email_of_invalid_token)

                    self.active_session_loaded_from_keyring = False
                    self.cached_token = None
                    self.cached_token_email = None
                    self.root.after(0, self._reset_ui_for_login)
                    return # Stop processing

                if status:
                    status_pretty = "--- Printer Status ---\n"
                    status_pretty += f"  Device ID: {status.get('dev_id', 'N/A')}\n"
                    status_pretty += f"  Device Name: {status.get('dev_name', 'N/A')}\n"
                    status_pretty += f"  Online: {status.get('dev_online', 'N/A')}\n"
                    status_pretty += f"  Task Name: {status.get('task_name', 'N/A')}\n"
                    status_pretty += f"  Task Status: {status.get('task_status', 'N/A')}\n"

                    start_time_str = status.get('start_time', None)
                    prediction_total_seconds_str = status.get('prediction', None) # This is total duration from API ('costTime')
                    progress_percentage_str = status.get('progress', 'N/A') # Default to N/A

                    import datetime

                    if start_time_str and start_time_str != 'N/A' and \
                       prediction_total_seconds_str and prediction_total_seconds_str != 'N/A':
                        try:
                            # Parse start_time (supports ISO format like "2022-11-22T01:58:10Z" or "YYYY-MM-DD HH:MM:SS")
                            if 'Z' in start_time_str:
                                st_dt = datetime.datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                                # Convert to local timezone if it's naive, or ensure it's aware for correct calculations
                                # For simplicity, let's assume UTC and convert to local for display if needed,
                                # but calculations are fine with consistent aware objects.
                                # Python's fromisoformat on 'Z' makes it timezone-aware (UTC).
                            elif 'T' in start_time_str: # ISO without Z
                                st_dt = datetime.datetime.fromisoformat(start_time_str)
                            else: # Fallback for "YYYY-MM-DD HH:MM:SS"
                                st_dt = datetime.datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                                # Make it system-timezone aware if parsed as naive
                                st_dt = st_dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None) if st_dt.tzinfo is None else st_dt


                            prediction_total_seconds = int(float(prediction_total_seconds_str))

                            # Calculate Progress
                            now_utc = datetime.datetime.now(datetime.timezone.utc)
                            st_dt_utc = st_dt.astimezone(datetime.timezone.utc) # Ensure start_time is UTC for comparison

                            elapsed_seconds = (now_utc - st_dt_utc).total_seconds()
                            if elapsed_seconds < 0: elapsed_seconds = 0 # Print hasn't started according to time sync

                            if prediction_total_seconds > 0:
                                current_progress = (elapsed_seconds / prediction_total_seconds) * 100
                                progress_percentage_str = f"{min(max(current_progress, 0), 100):.2f}%" # Clamp between 0 and 100
                            else: # Avoid division by zero if prediction is 0
                                progress_percentage_str = "0.00%" if elapsed_seconds >=0 else "N/A"


                            status_pretty += f"  Progress: {progress_percentage_str}\n"
                            status_pretty += f"  Start Time: {st_dt.strftime('%Y-%m-%d %H:%M:%S %Z%z')}\n" # Show timezone

                            # Calculate Remaining Time and Target End Time
                            remaining_seconds = prediction_total_seconds - elapsed_seconds
                            if remaining_seconds < 0: remaining_seconds = 0

                            target_time_utc = st_dt_utc + datetime.timedelta(seconds=prediction_total_seconds)
                            target_time_local = target_time_utc.astimezone(tz=None)
                            status_pretty += f"  Target End Time: {target_time_local.strftime('%Y-%m-%d %H:%M:%S %Z%z')}\n"

                            # Format remaining time as dd:hh:mm:ss
                            days_rem, secs_rem_total = divmod(int(remaining_seconds), 86400) # 86400 seconds in a day
                            hours_rem, secs_rem_total = divmod(secs_rem_total, 3600)
                            mins_rem, secs_rem = divmod(secs_rem_total, 60)
                            status_pretty += f"  Remaining (dd:hh:mm:ss): {days_rem:02d}:{hours_rem:02d}:{mins_rem:02d}:{secs_rem:02d}\n"
                            status_pretty += f"  Total Duration (s): {prediction_total_seconds}\n"


                        except ValueError as ve:
                            status_pretty += f"  Progress: {progress_percentage_str}\n" # Show N/A or last value if error
                            status_pretty += f"  Start Time: {start_time_str}\n"
                            status_pretty += f"  Prediction (s): {prediction_total_seconds_str} (Error parsing time/prediction: {ve})\n"
                        except Exception as e:
                            status_pretty += f"  Progress: {progress_percentage_str}\n"
                            status_pretty += f"  Start Time: {start_time_str}\n"
                            status_pretty += f"  Prediction (s): {prediction_total_seconds_str} (Error formatting time: {e})\n"
                    else: # If start_time or prediction is N/A
                        status_pretty += f"  Progress: {progress_percentage_str}\n" # Usually N/A if dependent data missing
                        status_pretty += f"  Start Time: {status.get('start_time', 'N/A')}\n"
                        status_pretty += f"  Prediction (s): {status.get('prediction', 'N/A')} (total duration)\n"

                    self.root.after(0, lambda s=status_pretty: self._set_status_display(s))
                    self.root.after(0, lambda: self._set_log_message("Printer status updated.", append=True))


                    if self.active_session_loaded_from_keyring: # UI update if token from keyring was used successfully
                         self.root.after(0, lambda: self._update_ui_after_login(session_loaded=True))
                else: # Status is None or an error structure not caught as 401 by BambuClient
                    self.root.after(0, lambda: self._set_log_message(f"Could not retrieve printer status for {serial}. See console.", is_error=True, append=True))
                    self.root.after(0, self._clear_status_display) # Clear status area
            else: # Should be caught by login logic if token is missing
                 self.root.after(0, lambda: self._set_log_message("Not logged in. Please login.", is_error=True, append=True))
                 self.root.after(0, self._reset_ui_for_login) # This will also clear status display

        except Exception as e:
            self.root.after(0, lambda err=str(e): self._set_log_message(f"Unexpected error: {err}", is_error=True, append=True))
            self.root.after(0, self._reset_ui_for_login) # Ensure UI is reset, this will also clear status display
        finally:
            self.root.after(0, lambda: self.action_button.config(state=tk.NORMAL))

if __name__ == '__main__':
    root = tk.Tk()
    app = BambuStatusApp(root)
    root.mainloop()
