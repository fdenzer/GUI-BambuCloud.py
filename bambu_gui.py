import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading # For running backend tasks without freezing UI
from bambu_cli import BambuClient # Assuming bambu_cli.py is in the same directory or PYTHONPATH
import os
from dotenv import load_dotenv
import keyring # For saving credentials

# --- Keyring Constants ---
KEYRING_SERVICE_NAME = "BambuStudioHelper_GUI"
KEY_EMAIL = "user_email"
KEY_SERIAL = "printer_serial"
KEY_PASSWORD = "user_password"
KEY_ACCESS_TOKEN_GUI = "gui_access_token" # Specific key for GUI's access token


class BambuStatusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bambu Lab Printer Status")
        self.root.geometry("500x700") # Increased height for two text areas

        load_dotenv()

        self.client = None
        self.login_requires_2fa = False
        self.active_session_loaded_from_keyring = False # Track if current session is from keyring

        # --- In-memory cache for credentials ---
        self.cached_email = None
        self.cached_serial = None
        self.cached_password = None
        self.cached_token = None
        self.cached_token_email = None # Email associated with the cached token
        # Flag to indicate if keyring was successfully accessed for loading in this session,
        # to prevent re-prompting if "Always Allow" was chosen.
        self.keyring_load_attempted_in_session = False
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

    # --- Credential Management Methods ---
    def _save_credentials_and_token(self, email, serial, password, token_to_save=None):
        try:
            if self.save_creds_var.get():
                if email: keyring.set_password(KEYRING_SERVICE_NAME, KEY_EMAIL, email)
                if serial: keyring.set_password(KEYRING_SERVICE_NAME, KEY_SERIAL, serial)
                if password: keyring.set_password(KEYRING_SERVICE_NAME, KEY_PASSWORD, password)
            else: # If save_creds is off, ensure they are deleted (token handled separately)
                if keyring.get_password(KEYRING_SERVICE_NAME, KEY_EMAIL): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_EMAIL)
                if keyring.get_password(KEYRING_SERVICE_NAME, KEY_SERIAL): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_SERIAL)
                if keyring.get_password(KEYRING_SERVICE_NAME, KEY_PASSWORD): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_PASSWORD)

            if token_to_save: # Always save token if one is provided (means successful login)
                keyring.set_password(KEYRING_SERVICE_NAME, KEY_ACCESS_TOKEN_GUI, token_to_save)
                self.cached_token = token_to_save # Update cache
                if email:
                    keyring.set_password(KEYRING_SERVICE_NAME, f"{KEY_ACCESS_TOKEN_GUI}_email", email)
                    self.cached_token_email = email # Update cache

            # Update cache for other credentials if they were part of the save operation
            if self.save_creds_var.get():
                if email: self.cached_email = email
                if serial: self.cached_serial = serial
                if password: self.cached_password = password
            else: # If save_creds was off, these specific items might have been deleted from keyring
                  # but we only clear the main password from cache. Email/serial might still be useful if token exists.
                self.cached_password = None
                # Token cache is handled above. Email/Serial cache remains as is,
                # as they might be unsaved but still used with a loaded token.

            # After any save operation, the keyring has been interacted with,
            # potentially changing its state from what was last loaded.
            # Forcing a re-evaluation of keyring state if _load_credentials_and_token is called next.
            # However, if we just saved, the cache should be up-to-date.
            # Let's assume keyring_load_attempted_in_session means "cache is representative of one load attempt"
            # and saving TO keyring means our cache is now the most current representation.
            # self.keyring_load_attempted_in_session = True # It's already true if we loaded, and saving makes cache valid.


            return True
        except Exception as e:
            self.root.after(0, lambda: self._set_log_message(f"Error saving data to keyring: {e}", is_error=True, append=True))
            return False

    def _load_credentials_and_token(self):
        if self.keyring_load_attempted_in_session:
            return {
                "email": self.cached_email,
                "serial": self.cached_serial,
                "password": self.cached_password,
                "token": self.cached_token,
                "token_email": self.cached_token_email
            }

        try:
            email = keyring.get_password(KEYRING_SERVICE_NAME, KEY_EMAIL)
            serial = keyring.get_password(KEYRING_SERVICE_NAME, KEY_SERIAL)
            # Load password only if "save credentials" would have been true for it
            password = keyring.get_password(KEYRING_SERVICE_NAME, KEY_PASSWORD) if email else None
            token = keyring.get_password(KEYRING_SERVICE_NAME, KEY_ACCESS_TOKEN_GUI)
            token_email = keyring.get_password(KEYRING_SERVICE_NAME, f"{KEY_ACCESS_TOKEN_GUI}_email")

            # If a token exists with an associated email, and the main email field is empty or different,
            # prefer the token's email.
            if token and token_email and (not email or email != token_email):
                self.cached_email = token_email # Update cache if we override email based on token
            else:
                self.cached_email = email

            self.cached_serial = serial
            self.cached_password = password # This will be None if email wasn't found, which is correct
            self.cached_token = token
            self.cached_token_email = token_email # Store original token_email from keyring

            self.keyring_load_attempted_in_session = True # Mark that we've done the keyring access

            return {
                "email": self.cached_email, # Return the potentially token-adjusted email
                "serial": self.cached_serial,
                "password": self.cached_password,
                "token": self.cached_token,
                "token_email": self.cached_token_email # Return the original token_email
            }
        except Exception as e:
            self._set_log_message(f"Error loading saved data from keyring: {e}", is_error=True, append=True)
            # Even on error, mark as attempted to avoid re-prompting loops within the same session
            self.keyring_load_attempted_in_session = True
            # Clear cache on error to ensure no stale/partial data is used
            self.cached_email = None
            self.cached_serial = None
            self.cached_password = None
            self.cached_token = None
            self.cached_token_email = None
            return {"email": None, "serial": None, "password": None, "token": None, "token_email": None}

    def _delete_credentials_and_token(self):
        try:
            if keyring.get_password(KEYRING_SERVICE_NAME, KEY_EMAIL): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_EMAIL)
            if keyring.get_password(KEYRING_SERVICE_NAME, KEY_SERIAL): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_SERIAL)
            if keyring.get_password(KEYRING_SERVICE_NAME, KEY_PASSWORD): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_PASSWORD)

            if keyring.get_password(KEYRING_SERVICE_NAME, KEY_ACCESS_TOKEN_GUI): keyring.delete_password(KEYRING_SERVICE_NAME, KEY_ACCESS_TOKEN_GUI)
            if keyring.get_password(KEYRING_SERVICE_NAME, f"{KEY_ACCESS_TOKEN_GUI}_email"): keyring.delete_password(KEYRING_SERVICE_NAME, f"{KEY_ACCESS_TOKEN_GUI}_email")

            if self.client: self.client.access_token = None # Clear token from active client
            self.active_session_loaded_from_keyring = False

            # Clear the cache
            self.cached_email = None
            self.cached_serial = None
            self.cached_password = None
            self.cached_token = None
            self.cached_token_email = None
            self.keyring_load_attempted_in_session = False # Allow next load to hit keyring

            return True
        except Exception as e:
            self.root.after(0, lambda: self._set_log_message(f"Error deleting saved data from keyring: {e}", is_error=True, append=True))
            return False

    def _try_load_session(self):
        data = self._load_credentials_and_token()
        email, serial, password, token = data.get("email"), data.get("serial"), data.get("password"), data.get("token")

        populated_from_keyring = False
        if email:
            self.email_entry.delete(0, tk.END); self.email_entry.insert(0, email)
            populated_from_keyring = True
        if serial:
            self.serial_entry.delete(0, tk.END); self.serial_entry.insert(0, serial)
            populated_from_keyring = True

        # Set "Save Credentials" checkbox state based on whether a password was loaded from keyring.
        # data["password"] from _load_credentials_and_token() will be non-None if a password
        # was successfully retrieved from keyring (which itself depends on email being present).
        if data.get("email") and data.get("password"):
            self.save_creds_var.set(True)
            # 'password' here is data.get("password") from the loaded credentials
            if data.get("password"):
                 self.password_entry.delete(0, tk.END); self.password_entry.insert(0, data.get("password"))
        else:
            self.save_creds_var.set(False)
            self.password_entry.delete(0, tk.END) # Clear field if not saving password

        if not populated_from_keyring: # Fallback to .env if nothing from keyring for email/serial
            env_email = os.getenv("username", "")
            env_serial = os.getenv("printer_sn", "")
            if not self.email_entry.get() and env_email : self.email_entry.insert(0, env_email)
            if not self.serial_entry.get() and env_serial : self.serial_entry.insert(0, env_serial)
            # .env doesn't influence save_creds_var or password field for GUI

        if token and email: # A token exists and we have an email for the client
            self.client = BambuClient(email=email, serial_number=serial if serial else "", access_token=token)
            self.active_session_loaded_from_keyring = True
            self._update_ui_after_login(session_loaded=True) # Disables fields, sets button text
            self._set_log_message(f"Verifying saved session for {email}...", append=False) # Clear log and set message
            self._clear_status_display() # Clear status area before auto-refresh
            self.handle_action() # Auto-click "Refresh Status" to validate token
        else:
            self._reset_ui_for_login() # No token, ensure clean login state. This also calls _set_log_message & _clear_status_display
            if self.save_creds_var.get() and password: # If save is on and password was loaded
                self.password_entry.config(state=tk.NORMAL) # Ensure it's editable initially
            elif not self.save_creds_var.get():
                 self.password_entry.delete(0, tk.END)


    def on_save_creds_toggled(self):
        email = self.email_entry.get()
        serial = self.serial_entry.get()
        password_val = self.password_entry.get() # Care: might be empty

        if self.save_creds_var.get(): # Box just got CHECKED
            # We only definitively save credentials (specifically password) upon a successful login.
            # However, we can save email/serial now if they exist.
            # The act of checking the box means "I want to save these next time I log in successfully"
            if email:
                keyring.set_password(KEYRING_SERVICE_NAME, KEY_EMAIL, email)
                self.cached_email = email # Update cache
            if serial:
                keyring.set_password(KEYRING_SERVICE_NAME, KEY_SERIAL, serial)
                self.cached_serial = serial # Update cache
            # Password itself is only saved via _save_credentials_and_token after login.
            self.password_entry.config(state=tk.DISABLED if self.active_session_loaded_from_keyring else tk.NORMAL)
            self._set_log_message("Credentials will be stored securely on next successful login.", append=True)
        else: # Box just got UNCHECKED
            if self._delete_credentials_and_token(): # Clear everything: creds and token
                self._set_log_message("Saved credentials and session cleared.", append=True)
            # self.password_entry.delete(0, tk.END) # _reset_ui_for_login handles this if save_creds is off
            self._reset_ui_for_login() # Full UI reset to login state. This also calls _set_log_message & _clear_status_display

    def _perform_action_thread(self, email, password, serial, tfa_code):
        try:
            # --- Client Initialization & Token Validation ---
            # If a session was loaded from keyring (self.active_session_loaded_from_keyring is true)
            # then self.client is already initialized with that token.
            # The BambuClient's _make_request will handle if that token is bad.

            if not self.client or self.client.email != email or \
               (self.active_session_loaded_from_keyring and not self.client.access_token):
                # This block handles:
                # 1. Initial client creation if no session was loaded.
                # 2. Client re-creation if email changed in the form.
                # 3. Client re-creation if a keyring-loaded session was just invalidated.

                if self.active_session_loaded_from_keyring and not self.client.access_token:
                    # A token loaded at app start was found invalid by an API call that BambuClient made.
                    # BambuClient already cleared its internal token. We need to clear from keyring.
                    self.root.after(0, lambda: self._set_log_message("Saved session was invalid. Please login.", is_error=True, append=True))
                    self._delete_credentials_and_token() # Clear the bad token from keyring
                    self.active_session_loaded_from_keyring = False # Reset flag
                    self.root.after(0, self._clear_status_display) # Clear status display
                    # UI should be reset for login by the end of this or by _reset_ui_for_login call

                # Create a new client instance for a password-based login.
                # The password used by client.login() will be what's in self.client.password.
                self.client = BambuClient(email=email, serial_number=serial, password=password)
                self.login_requires_2fa = False # Reset 2FA for new attempt.

            # --- Login (if no valid token) ---
            if not self.client.access_token:
                self.active_session_loaded_from_keyring = False # Ensure this is false if we're about to login

                if self.login_requires_2fa:
                    if not tfa_code:
                        self.root.after(0, lambda: self._set_log_message("2FA code is required.", is_error=True, append=True))
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return
                    self.root.after(0, lambda: self._set_log_message("Attempting 2FA login...", append=True))
                    logged_in = self.client.login_with_2fa(tfa_code)
                    if logged_in:
                        self.login_requires_2fa = False
                        self._save_credentials_and_token(email, serial, password, self.client.access_token)
                        self.root.after(0, lambda: self._update_ui_after_login(session_loaded=False))
                        # Success message for 2FA login will be handled by _update_ui_after_login or a subsequent status fetch
                    else:
                        self.root.after(0, lambda: self._set_log_message("2FA login failed.", is_error=True, append=True))
                        self.root.after(0, self._update_ui_for_2fa_input) # Stay in 2FA mode
                        return
                else: # Standard password login
                    if not self.client.password: # Password should have been passed to BambuClient constructor
                        self.root.after(0, lambda: self._set_log_message("Password is required for login.", is_error=True, append=True))
                        self.root.after(0, self._reset_ui_for_login)
                        return

                    self.root.after(0, lambda: self._set_log_message("Attempting login...", append=True))
                    logged_in, needs_2fa_flag = self.client.login() # Uses password from client instance
                    if logged_in:
                        self.login_requires_2fa = False
                        self._save_credentials_and_token(email, serial, self.client.password, self.client.access_token)
                        self.root.after(0, lambda: self._update_ui_after_login(session_loaded=False))
                        self.root.after(0, lambda: self._set_log_message("Login successful.", append=True))
                    elif needs_2fa_flag:
                        self.login_requires_2fa = True
                        self.root.after(0, lambda: self._set_log_message("Login requires 2FA. Enter code.", append=True))
                        self.root.after(0, self._update_ui_for_2fa_input)
                        return
                    else: # Login failed (non-2FA)
                        self.root.after(0, lambda: self._set_log_message("Login failed. Check credentials.", is_error=True, append=True))
                        self.root.after(0, self._reset_ui_for_login) # This will also clear status display
                        return

            # --- API Call (if token exists) ---
            if self.client.access_token:
                self.root.after(0, lambda: self._set_log_message(f"Fetching status for {serial}...", append=True))
                status = self.client.get_printer_status(serial)

                if not self.client.access_token and self.active_session_loaded_from_keyring:
                    # Token became invalid DURING the get_printer_status call.
                    # BambuClient's _make_request detected 401 and cleared its internal token.
                    self.root.after(0, lambda: self._set_log_message("Session expired during fetch. Please login.", is_error=True, append=True))
                    self._delete_credentials_and_token() # Clear from keyring
                    self.active_session_loaded_from_keyring = False
                    self.root.after(0, self._reset_ui_for_login) # This will also clear status display
                    return # Stop processing

                if status:
                    status_pretty = "--- Printer Status ---\n" # Removed leading newline
                    status_pretty += f"  Device ID: {status.get('dev_id', 'N/A')}\n"
                    status_pretty += f"  Device Name: {status.get('dev_name', 'N/A')}\n"
                    status_pretty += f"  Online: {status.get('dev_online', 'N/A')}\n"
                    status_pretty += f"  Task Name: {status.get('task_name', 'N/A')}\n"
                    status_pretty += f"  Task Status: {status.get('task_status', 'N/A')}\n"
                    status_pretty += f"  Progress: {status.get('progress', 'N/A')}\n"
                    status_pretty += f"  Start Time: {status.get('start_time', 'N/A')}\n"
                    prediction = status.get('prediction', None)
                    start_time = status.get('start_time', None)
                    if prediction is not None and start_time not in (None, 'N/A'):
                        import datetime
                        try:
                            if isinstance(start_time, str):
                                try: st_dt = datetime.datetime.fromisoformat(start_time)
                                except Exception: st_dt = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                            else: st_dt = start_time

                            try: prediction_seconds = int(float(prediction))
                            except ValueError: raise ValueError("Prediction value is not a valid number.")

                            target_time = st_dt + datetime.timedelta(seconds=prediction_seconds)
                            status_pretty += f"  Target End Time: {target_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                            duration_obj = datetime.timedelta(seconds=prediction_seconds)

                            days = duration_obj.days
                            secs_remainder = duration_obj.seconds
                            hours = secs_remainder // 3600
                            minutes = (secs_remainder % 3600) // 60
                            seconds = secs_remainder % 60
                            status_pretty += f"  Remaining (dd:hh:mm:ss): {days:02}:{hours:02}:{minutes:02}:{seconds:02}\n"
                        except Exception as e:
                            status_pretty += f"  Prediction (s): {prediction} (error formatting time: {e})\n"
                    else:
                        status_pretty += f"  Prediction (s): {status.get('prediction', 'N/A')}\n"
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
