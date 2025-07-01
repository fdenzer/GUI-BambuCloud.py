#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::{egui, App, Frame};
use tokio::runtime::Runtime;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc}; // For sharing data with threads if needed, though mpsc is often better for results

mod keychain_manager_rs;
use keychain_manager_rs::{KeychainManagerRs, GuiCredentialsRs};

mod bambu_api;
use bambu_api::{BambuApiClientRs, DeviceStatus, ApiError};

// Enum to represent messages sent from worker threads to the UI thread
#[derive(Debug)]
enum AppMessage {
    Log(String),
    Error(String),
    LoginSuccess { email: String, token: String, from_keychain: bool },
    LoginRequires2FA { email: String },
    LoginFailure { message: String },
    StatusUpdate(DeviceStatus),
    StatusUpdateAuthError(String), // Token became invalid
    StatusUpdateError(String),
    KeychainLoadResult(Option<String>, Option<GuiCredentialsRs>), // token, gui_creds
}

// State for the UI and application logic
struct MyApp {
    // Inputs
    email_input: String,
    password_input: String,
    serial_input: String,
    tfa_input: String,

    // App State
    access_token: Option<String>, // Current active token
    active_email: Option<String>, // Email associated with the current token/login attempt
    login_requires_2fa: bool,
    save_credentials_checkbox: bool,
    is_loading: bool, // To disable UI elements during async operations

    // Display
    log_messages: Vec<String>,
    status_display: Option<DeviceStatus>, // Formatted status

    // Services
    keychain_manager: Arc<KeychainManagerRs>, // Arc for thread safety if needed, though direct calls might be fine
    api_client: Arc<BambuApiClientRs>,     // Arc for thread safety
    tokio_rt: Arc<Runtime>,                // Arc for thread safety

    // Communication channel for async results
    message_sender: Sender<AppMessage>,
    message_receiver: Receiver<AppMessage>,
}

impl Default for MyApp {
    fn default() -> Self {
        let (tx, rx) = channel();
        let app = Self {
            email_input: String::new(),
            password_input: String::new(),
            serial_input: String::new(),
            tfa_input: String::new(),

            access_token: None,
            active_email: None,
            login_requires_2fa: false,
            save_credentials_checkbox: false,
            is_loading: true, // Start as loading to perform initial keychain load

            log_messages: vec!["Application started.".to_string()],
            status_display: None,

            keychain_manager: Arc::new(KeychainManagerRs::new()),
            api_client: Arc::new(BambuApiClientRs::new()),
            tokio_rt: Arc::new(Runtime::new().expect("Failed to create Tokio runtime")),

            message_sender: tx,
            message_receiver: rx,
        };
        app.try_load_initial_session(); // Trigger initial load
        app
    }
}

impl MyApp {
    fn add_log(&mut self, message: String) {
        log::info!("{}", message); // Also log to console via env_logger
        self.log_messages.push(message);
        if self.log_messages.len() > 100 { // Keep log history manageable
            self.log_messages.remove(0);
        }
    }

    fn try_load_initial_session(&self) {
        let km = Arc::clone(&self.keychain_manager);
        let tx = self.message_sender.clone();

        self.tokio_rt.spawn(async move {
            tx.send(AppMessage::Log("Attempting to load saved session from keychain...".to_string())).ok();
            let gui_creds_res = km.load_gui_credentials();
            let last_token_email_res = km.get_last_saved_token_email();

            match (gui_creds_res, last_token_email_res) {
                (Ok(gui_creds), Ok(last_token_email_opt)) => {
                    let token_to_try_opt = if let Some(ref email) = last_token_email_opt {
                        match km.load_token(email) {
                            Ok(Some(token)) => {
                                tx.send(AppMessage::Log(format!("Found token for last user: {}", email))).ok();
                                Some(token)
                            },
                            Ok(None) => {
                                tx.send(AppMessage::Log(format!("No token found for last user: {}", email))).ok();
                                None
                            },
                            Err(e) => {
                                tx.send(AppMessage::Error(format!("Error loading token for {}: {}", email, e))).ok();
                                None
                            }
                        }
                    } else if let Some(ref email) = gui_creds.email { // Fallback to GUI email if no last_token_email
                         match km.load_token(email) {
                            Ok(Some(token)) => {
                                tx.send(AppMessage::Log(format!("Found token for GUI user: {}", email))).ok();
                                Some(token)
                            },
                            Ok(None) => {
                                tx.send(AppMessage::Log(format!("No token found for GUI user: {}", email))).ok();
                                None
                            },
                            Err(e) => {
                                tx.send(AppMessage::Error(format!("Error loading token for {}: {}", email, e))).ok();
                                None
                            }
                        }
                    }
                    else { None };
                    tx.send(AppMessage::KeychainLoadResult(token_to_try_opt, Some(gui_creds))).ok();
                }
                (Err(e_gui), _) => { tx.send(AppMessage::Error(format!("Error loading GUI credentials: {}", e_gui))).ok(); },
                (_, Err(e_token_email)) => { tx.send(AppMessage::Error(format!("Error loading last token email: {}", e_token_email))).ok(); },
            }
        });
    }

    fn handle_action_button(&mut self) {
        self.is_loading = true;
        self.status_display = None; // Clear old status
        self.add_log("Processing...".to_string());

        let email = self.email_input.clone();
        let password = self.password_input.clone(); // Clone for thread
        let serial = self.serial_input.clone();
        let tfa_code = self.tfa_input.clone();

        let current_token = self.access_token.clone();
        let requires_2fa_now = self.login_requires_2fa;
        let active_email_for_op = self.active_email.clone().unwrap_or_else(|| email.clone());


        let api_client_clone = Arc::clone(&self.api_client);
        let tx = self.message_sender.clone();

        self.tokio_rt.spawn(async move {
            if let Some(token) = current_token { // Already have a token, try to get status
                tx.send(AppMessage::Log(format!("Using existing token. Fetching status for {}...", serial))).ok();
                match (&*api_client_clone).get_printer_status(&serial, &token).await {
                    Ok(status_data) => {
                        tx.send(AppMessage::StatusUpdate(status_data)).ok();
                    }
                    Err(ApiError::AuthError(msg)) => { // Token was invalid
                        tx.send(AppMessage::StatusUpdateAuthError(msg)).ok();
                    }
                    Err(e) => {
                        tx.send(AppMessage::StatusUpdateError(format!("Error getting status: {:?}", e))).ok();
                    }
                }
            } else if requires_2fa_now { // Need to submit 2FA code
                if tfa_code.is_empty() {
                    tx.send(AppMessage::Error("2FA code is required.".to_string())).ok();
                    // UI state (is_loading) will be reset by message handler
                    return;
                }
                tx.send(AppMessage::Log(format!("Attempting login with 2FA for {}...", active_email_for_op))).ok();
                 match (&*api_client_clone).login_2fa(&active_email_for_op, &tfa_code).await {
                    Ok(response) => {
                        if let Some(new_token) = response.access_token {
                            tx.send(AppMessage::LoginSuccess { email: active_email_for_op, token: new_token, from_keychain: false }).ok();
                        } else {
                            tx.send(AppMessage::LoginFailure { message: response.message.unwrap_or_else(|| "2FA Login failed.".to_string()) }).ok();
                        }
                    }
                    Err(e) => {
                         tx.send(AppMessage::LoginFailure { message: format!("2FA Login error: {:?}", e) }).ok();
                    }
                }
            } else { // Initial login attempt with password
                if email.is_empty() || password.is_empty() {
                     tx.send(AppMessage::Error("Email and Password are required for login.".to_string())).ok();
                    return;
                }
                tx.send(AppMessage::Log(format!("Attempting login for {}...", email))).ok();
                match (&*api_client_clone).login(&email, &password).await {
                    Ok(response) => {
                        if let Some(new_token) = response.access_token {
                            tx.send(AppMessage::LoginSuccess { email: email.clone(), token: new_token, from_keychain: false }).ok();
                        } else if response.login_type.as_deref() == Some("verifyCode") {
                            tx.send(AppMessage::LoginRequires2FA { email: email.clone() }).ok();
                        } else {
                            tx.send(AppMessage::LoginFailure { message: response.message.unwrap_or_else(|| "Login failed.".to_string()) }).ok();
                        }
                    }
                    Err(e) => {
                        tx.send(AppMessage::LoginFailure { message: format!("Login error: {:?}", e) }).ok();
                    }
                }
            }
        });
    }

    fn handle_save_creds_toggle(&mut self) {
        if !self.save_credentials_checkbox { // Box was just UNCHECKED
            self.add_log("Clearing saved credentials and session due to uncheck...".to_string());
            let km = Arc::clone(&self.keychain_manager);
            let email_to_clear = self.active_email.clone().or_else(|| Some(self.email_input.clone()).filter(|s|!s.is_empty()));

            // Clear from keychain (can be async if desired, but usually fast)
            // For simplicity in this step, doing it synchronously.
            if let Err(e) = km.clear_gui_credentials() {
                self.add_log(format!("Error clearing GUI credentials from keychain: {}",e));
            }
            if let Some(email) = email_to_clear {
                if let Err(e) = km.clear_token(&email) {
                     self.add_log(format!("Error clearing token for {} from keychain: {}", email, e));
                }
            } else {
                self.add_log("No active email to clear token for.".to_string());
            }

            // Reset app state
            self.access_token = None;
            self.active_email = None;
            self.login_requires_2fa = false;
            self.password_input.clear(); // Clear password field
            // Email and serial can remain for user convenience if they want to log in again without saving
            self.add_log("Saved credentials and session cleared. Please login again if needed.".to_string());
        } else { // Box was just CHECKED
            self.add_log("'Save Credentials' checked. Email/Serial will be updated in keychain if entered. Password will be saved on next successful login.".to_string());
            // Save current email/serial to GUI creds if they exist. Password saved on login.
            let km = Arc::clone(&self.keychain_manager);
            let current_gui_creds = GuiCredentialsRs {
                email: Some(self.email_input.clone()).filter(|s|!s.is_empty()),
                password: None, // Password only saved on successful login with checkbox on
                serial: Some(self.serial_input.clone()).filter(|s|!s.is_empty()),
            };
            if let Err(e) = km.save_gui_credentials(current_gui_creds) {
                 self.add_log(format!("Error saving GUI email/serial to keychain: {}",e));
            }
        }
    }

    fn process_messages(&mut self) {
        match self.message_receiver.try_recv() {
            Ok(AppMessage::Log(msg)) => self.add_log(msg),
            Ok(AppMessage::Error(err_msg)) => {
                self.add_log(format!("ERROR: {}", err_msg));
                self.is_loading = false; // Ensure loading state is reset on error
            }
            Ok(AppMessage::LoginSuccess { email, token, from_keychain }) => {
                self.add_log(format!("Login successful for {}.", email));
                self.access_token = Some(token.clone());
                self.active_email = Some(email.clone());
                self.login_requires_2fa = false;
                self.is_loading = false;
                self.tfa_input.clear();

                if self.save_credentials_checkbox && !from_keychain { // If logged in with password and save is checked
                    self.add_log("Saving token and credentials to keychain...".to_string());
                    let km = Arc::clone(&self.keychain_manager);
                    if let Err(e) = km.save_token(&email, &token) {
                        self.add_log(format!("Error saving token to keychain: {}", e));
                    }
                    let gui_creds = GuiCredentialsRs { // Save with the password used for this login
                        email: Some(email),
                        password: Some(self.password_input.clone()), // This was the password that worked
                        serial: Some(self.serial_input.clone()).filter(|s|!s.is_empty()),
                    };
                    if let Err(e) = km.save_gui_credentials(gui_creds) {
                        self.add_log(format!("Error saving GUI credentials to keychain: {}", e));
                    }
                } else if from_keychain { // Loaded from keychain, no need to save password again
                     self.add_log("Session loaded from keychain.".to_string());
                }
                // Automatically fetch status after login
                self.handle_action_button();
            }
            Ok(AppMessage::LoginRequires2FA { email }) => {
                self.add_log(format!("Login for {} requires 2FA. Please enter code.", email));
                self.active_email = Some(email); // Store email for 2FA attempt
                self.login_requires_2fa = true;
                self.is_loading = false;
            }
            Ok(AppMessage::LoginFailure { message }) => {
                self.add_log(format!("Login failed: {}", message));
                self.access_token = None;
                // self.active_email = None; // Keep email in field for retry
                self.login_requires_2fa = false; // Reset 2FA state on failure
                self.is_loading = false;
            }
            Ok(AppMessage::StatusUpdate(status_data)) => {
                self.add_log("Printer status updated.".to_string());
                // status_data.calculate_derived_fields(); // Calculation done in API client now
                self.status_display = Some(status_data);
                self.is_loading = false;
            }
            Ok(AppMessage::StatusUpdateAuthError(msg)) => {
                self.add_log(format!("Authentication error during status update: {}. Token cleared.", msg));
                self.access_token = None;
                self.active_email = None; // Or keep for re-login prompt? For now, clear.
                self.login_requires_2fa = false;
                self.is_loading = false;
                // Clear token from keychain
                if let Some(email) = self.email_input.clone().into() { // Use current email input
                    let km = Arc::clone(&self.keychain_manager);
                    if let Err(e) = km.clear_token(&email) {
                        self.add_log(format!("Error clearing token for {} from keychain: {}", email, e));
                    }
                }
            }
            Ok(AppMessage::StatusUpdateError(err_msg)) => {
                self.add_log(format!("Error updating status: {}", err_msg));
                self.status_display = None;
                self.is_loading = false;
            }
            Ok(AppMessage::KeychainLoadResult(token_opt, gui_creds_opt)) => {
                self.add_log("Keychain load attempt finished.".to_string());
                if let Some(creds) = gui_creds_opt {
                    self.email_input = creds.email.unwrap_or_default();
                    self.serial_input = creds.serial.unwrap_or_default();
                    if creds.password.is_some() && !self.email_input.is_empty() { // Password was saved
                        self.password_input = creds.password.unwrap_or_default();
                        self.save_credentials_checkbox = true; // Reflect that password was loaded
                         self.add_log("Loaded saved GUI credentials (including password).".to_string());
                    } else {
                         self.add_log("Loaded GUI credentials (email/serial). Password not saved or not applicable.".to_string());
                    }
                }
                if let Some(token) = token_opt {
                    // An email should be associated with this token from the load logic
                    let email_for_token = self.keychain_manager.get_last_saved_token_email().unwrap_or_else(|_| None).unwrap_or_else(|| self.email_input.clone());
                    if !email_for_token.is_empty() {
                        self.message_sender.send(AppMessage::LoginSuccess { email: email_for_token, token, from_keychain: true }).ok();
                    } else {
                         self.add_log("Loaded token from keychain, but couldn't determine associated email. Please login manually.".to_string());
                         self.is_loading = false; // Only set to false if not proceeding to LoginSuccess
                    }
                } else {
                    self.add_log("No active session token found. Please login.".to_string());
                    self.is_loading = false; // No token, so finish loading state
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => { /* No message, do nothing */ }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("AppMessage channel disconnected!");
            }
        }
    }
}


impl App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        self.process_messages(); // Check for messages from async tasks
        ctx.request_repaint(); // Ensure continuous updates for async results

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.set_enabled(!self.is_loading); // Disable UI during operations

            ui.heading("Bambu Lab Printer Status");
            ui.add_space(10.0);

            // --- Credentials and Serial ---
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label("Credentials & Printer");
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label("Email:");
                    ui.add_enabled(!self.is_loading && self.access_token.is_none(),
                        egui::TextEdit::singleline(&mut self.email_input).hint_text("Enter email"));
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                     ui.add_enabled(!self.is_loading && self.access_token.is_none(),
                        egui::TextEdit::singleline(&mut self.password_input).password(true).hint_text("Enter password"));
                });
                ui.horizontal(|ui| {
                    ui.label("Serial Number:");
                    ui.add_enabled(!self.is_loading && self.access_token.is_none(),
                        egui::TextEdit::singleline(&mut self.serial_input).hint_text("Enter serial"));
                });

                let save_creds_text = if self.access_token.is_some() && self.save_credentials_checkbox {
                    "Credentials Saved (Token Active)"
                } else {
                    "Save Credentials Securely"
                };

                if ui.add_enabled(!self.is_loading, egui::Checkbox::new(&mut self.save_credentials_checkbox, save_creds_text)).clicked() {
                    if self.save_credentials_checkbox { // If it became true
                         self.add_log("Save Credentials enabled. Will save on next successful login if not using token.".to_string());
                         // Actual saving/clearing is more complex, handled by handle_save_creds_toggle
                         self.handle_save_creds_toggle();
                    } else { // If it became false
                        self.add_log("Save Credentials disabled. Clearing saved credentials.".to_string());
                        self.handle_save_creds_toggle();
                    }
                }


            });
            ui.add_space(5.0);

            // --- 2FA Frame (conditionally shown) ---
            if self.login_requires_2fa {
                 egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.label("Two-Factor Authentication");
                    ui.horizontal(|ui| {
                        ui.label("2FA Code:");
                        ui.add_enabled(!self.is_loading, egui::TextEdit::singleline(&mut self.tfa_input).hint_text("Enter 2FA code"));
                    });
                });
                ui.add_space(5.0);
            }

            // --- Action Button ---
            let action_button_text = if self.access_token.is_some() {
                "Refresh Printer Status"
            } else if self.login_requires_2fa {
                "Login with 2FA Code"
            } else {
                "Get Printer Status / Login"
            };
            if ui.add_enabled(!self.is_loading, egui::Button::new(action_button_text).min_size(egui::vec2(ui.available_width(), 0.0))).clicked() {
                self.handle_action_button();
            }
            ui.add_space(5.0);

            if self.is_loading {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading...");
                });
            }


            // --- Log Display ---
            ui.label("Log");
            egui::ScrollArea::vertical().max_height(100.0).stick_to_bottom(true).show(ui, |ui| {
                for msg in &self.log_messages {
                    ui.label(msg);
                }
            });
            if ui.button("Clear Log").clicked() {
                self.log_messages.clear();
                self.add_log("Log cleared.".to_string());
            }
            ui.add_space(5.0);

            // --- Status Display ---
            ui.label("Printer Status");
            egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                if let Some(status) = &self.status_display {
                    ui.label(format!("Device ID: {}", status.dev_id.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Device Name: {}", status.dev_name.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Online: {}", status.is_online()));
                    ui.label(format!("Task Name: {}", status.task_name.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Task Status: {}", status.task_status.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Progress: {}", status.progress.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Start Time: {}", status.start_time.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Total Duration: {}", status.total_duration_str.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Target End Time: {}", status.target_end_time_str.as_deref().unwrap_or("N/A")));
                    ui.label(format!("Remaining Time: {}", status.remaining_time_str.as_deref().unwrap_or("N/A")));
                } else {
                    ui.label("No status to display. Click button above to fetch/refresh.");
                }
            });
        });
    }
}

// Main function remains largely the same but uses the new MyApp
fn main() -> Result<(), eframe::Error> {
    env_logger::init(); // Initialize logger
    if std::env::var("RUST_LOG").is_err() {
        // Default to debug if not set
        unsafe { std::env::set_var("RUST_LOG", "debug"); }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Bambu Lab Client - Rust Egui",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    )
}
