use keyring::Keyring; // Only import Keyring struct
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use log::{error, info, warn}; // Added for logging

const SHARED_KEYRING_SERVICE_NAME: &str = "BambuStudioHelper";
const KEYCHAIN_DATA_ACCOUNT_NAME: &str = "BambuStudioUserData";

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GuiCredentialsRs { // Made pub
    pub email: Option<String>, // Made pub
    pub password: Option<String>, // Made pub
    pub serial: Option<String>, // Made pub
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct KeychainData {
    tokens: HashMap<String, String>, // email_lowercase -> token
    last_token_user_email: Option<String>, // email_lowercase
    gui_credentials: Option<GuiCredentialsRs>,
}

pub struct KeychainManagerRs {
    service_name: String,
    account_name: String,
    keyring: Keyring<'static>, // Correct for iffyio/keyring-rs
}

impl KeychainManagerRs {
    pub fn new() -> Self {
        info!("Initializing KeychainManagerRs for service: {} and account: {}", SHARED_KEYRING_SERVICE_NAME, KEYCHAIN_DATA_ACCOUNT_NAME);
        Self {
            service_name: SHARED_KEYRING_SERVICE_NAME.to_string(),
            account_name: KEYCHAIN_DATA_ACCOUNT_NAME.to_string(),
            keyring: Keyring::new(SHARED_KEYRING_SERVICE_NAME, KEYCHAIN_DATA_ACCOUNT_NAME),
        }
    }

    fn load_keychain_data(&self) -> Result<KeychainData, String> {
        match self.keyring.get_password() {
            Ok(json_blob) => {
                if json_blob.is_empty() {
                    info!("Keychain data is empty, returning default.");
                    Ok(KeychainData::default())
                } else {
                    info!("Successfully retrieved data from keychain, attempting deserialization.");
                    serde_json::from_str(&json_blob)
                        .map_err(|e| {
                            error!("Error deserializing keychain data: {}", e);
                            format!("Error deserializing keychain data: {}", e)
                        })
                }
            }
            Err(keyring::KeyringError::NoPasswordFound) => { // Correct for iffyio/keyring-rs
                info!("No password found in keychain for service '{}', account '{}'. Returning default KeychainData.", self.service_name, self.account_name);
                Ok(KeychainData::default())
            }
            Err(e) => {
                error!("Error loading from keychain for service '{}', account '{}': {:?}", self.service_name, self.account_name, e); // Changed to {:?} for e
                Err(format!("Error loading from keychain: {:?}", e)) // Changed to {:?} for e
            }
        }
    }

    fn save_keychain_data(&self, data: &KeychainData) -> Result<(), String> {
        let json_blob = serde_json::to_string(data)
            .map_err(|e| {
                error!("Error serializing keychain data: {}", e);
                format!("Error serializing keychain data: {}", e)
            })?;
        self.keyring.set_password(&json_blob)
            .map_err(|e| {
                error!("Error saving to keychain for service '{}', account '{}': {:?}", self.service_name, self.account_name, e); // Changed to {:?} for e
                format!("Error saving to keychain: {:?}", e) // Changed to {:?} for e
            })?;
        info!("Successfully saved data to keychain for service '{}', account '{}'.", self.service_name, self.account_name);
        Ok(())
    }

    // --- Token Management ---
    pub fn save_token(&self, email: &str, token: &str) -> Result<(), String> {
        if email.is_empty() || token.is_empty() {
            warn!("Attempted to save token with empty email or token.");
            return Err("Email and token cannot be empty".to_string());
        }
        let mut data = self.load_keychain_data()?;
        let email_lower = email.to_lowercase();
        data.tokens.insert(email_lower.clone(), token.to_string());
        data.last_token_user_email = Some(email_lower);
        self.save_keychain_data(&data)?;
        info!("Token for email '{}' saved successfully.", email);
        Ok(())
    }

    pub fn load_token(&self, email: &str) -> Result<Option<String>, String> {
        if email.is_empty() {
            warn!("Attempted to load token with empty email.");
            return Ok(None);
        }
        let data = self.load_keychain_data()?;
        let email_lower = email.to_lowercase();
        Ok(data.tokens.get(&email_lower).cloned())
    }

    pub fn clear_token(&self, email: &str) -> Result<(), String> {
        if email.is_empty() {
            warn!("Attempted to clear token with empty email.");
            return Ok(()); // Not an error, just nothing to do
        }
        let mut data = self.load_keychain_data()?;
        let email_lower = email.to_lowercase();
        if data.tokens.remove(&email_lower).is_some() {
            info!("Token for email '{}' cleared.", email);
        }
        if data.last_token_user_email.as_deref() == Some(&email_lower) {
            data.last_token_user_email = None;
            info!("Last token user email reference cleared for '{}'.", email);
        }
        self.save_keychain_data(&data)
    }

    pub fn get_last_saved_token_email(&self) -> Result<Option<String>, String> {
        let data = self.load_keychain_data()?;
        Ok(data.last_token_user_email.clone())
    }

    // --- GUI Credential Management ---
    pub fn save_gui_credentials(&self, creds: GuiCredentialsRs) -> Result<(), String> {
        let mut data = self.load_keychain_data()?;
        data.gui_credentials = Some(creds);
        self.save_keychain_data(&data)?;
        info!("GUI credentials saved.");
        Ok(())
    }

    pub fn load_gui_credentials(&self) -> Result<GuiCredentialsRs, String> {
        let data = self.load_keychain_data()?;
        Ok(data.gui_credentials.unwrap_or_default())
    }

    pub fn clear_gui_credentials(&self) -> Result<(), String> {
        let mut data = self.load_keychain_data()?;
        if data.gui_credentials.is_some() {
            data.gui_credentials = None;
            self.save_keychain_data(&data)?;
            info!("GUI credentials cleared.");
        }
        Ok(())
    }

    // --- Clear All ---
    pub fn clear_all_keychain_entries(&self) -> Result<(), String> {
        // keyring-rs deletes the entry for the (service_name, account_name) pair.
        // So, setting an empty KeychainData effectively does this, or we can use delete_password.
        match self.keyring.delete_password() {
            Ok(_) => {
                info!("All keychain data cleared for service '{}', account '{}'.", self.service_name, self.account_name);
                Ok(())
            }
            Err(keyring::KeyringError::NoPasswordFound) => { // Correct for iffyio/keyring-rs
                info!("No keychain data found to clear for service '{}', account '{}'.", self.service_name, self.account_name);
                Ok(()) // Not an error if it wasn't there
            }
            Err(e) => {
                error!("Error deleting keychain entry for service '{}', account '{}': {:?}", self.service_name, self.account_name, e); // Changed to {:?} for e
                Err(format!("Error deleting keychain entry: {:?}", e)) // Changed to {:?} for e
            }
        }
    }
}

// Default implementation for KeychainManagerRs to be used if new() fails or not preferred.
impl Default for KeychainManagerRs {
    fn default() -> Self {
        Self::new()
    }
}
