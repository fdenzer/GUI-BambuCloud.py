use reqwest::{Client, header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap; // Restoring import, warning was likely incorrect
use log::{info, warn}; // Removed debug, error as per warning
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime, SecondsFormat}; // For parsing time strings

const API_BASE_URL: &str = "https://api.bambulab.com";

// --- Request Structs ---

#[derive(Serialize, Debug)]
struct LoginRequest<'a> {
    account: &'a str,
    password: &'a str,
}

#[derive(Serialize, Debug)]
struct Login2FARequest<'a> {
    account: &'a str,
    code: &'a str,
}

// --- Response Structs ---

#[derive(Deserialize, Debug, Clone)]
pub struct LoginResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "loginType")]
    pub login_type: Option<String>, // e.g., "verifyCode" for 2FA
    pub message: Option<String>,    // Error message
    pub code: Option<String>,       // Error code as string (e.g. "401")
    // Other fields like 'userDisplayName', 'userId', etc., can be added if needed
}

#[derive(Deserialize, Debug, Clone, Default)] // Added Default
pub struct DeviceStatus {
    pub dev_id: Option<String>,
    pub dev_name: Option<String>,
    pub dev_online: Option<String>, // "true" or "false", consider parsing to bool
    pub task_name: Option<String>,
    pub task_status: Option<String>, // e.g., "Printing", "Idle", from /my/tasks
    pub progress: Option<String>, // Percentage string like "80.00%" or "N/A"
    pub start_time: Option<String>, // ISO 8601 or "YYYY-MM-DD HH:MM:SS"
    pub prediction: Option<String>, // Total print duration in seconds (from 'costTime')

    // These will be populated by calculations later
    #[serde(skip)] // Not directly from API, calculated
    pub target_end_time_str: Option<String>,
    #[serde(skip)]
    pub remaining_time_str: Option<String>,
    #[serde(skip)]
    pub total_duration_str: Option<String>, // Formatted from prediction
}

impl DeviceStatus {
    pub fn is_online(&self) -> bool {
        self.dev_online.as_deref().unwrap_or("false").to_lowercase() == "true"
    }

    // Method to perform calculations, similar to Python GUI
    // This should be called after initial deserialization
    pub fn calculate_derived_fields(&mut self) {
        if let (Some(st_str), Some(pred_str)) = (&self.start_time, &self.prediction) {
            if st_str == "N/A" || pred_str == "N/A" { return; }

            let start_time_dt_utc = parse_datetime_utc(st_str);
            let prediction_secs_opt = pred_str.parse::<f64>().ok();

            if let (Some(st_dt), Some(pred_secs)) = (start_time_dt_utc, prediction_secs_opt) {
                let pred_duration = chrono::Duration::seconds(pred_secs as i64);
                self.total_duration_str = Some(format_duration(pred_duration.num_seconds()));

                let target_dt_utc = st_dt + pred_duration;
                let target_dt_local = target_dt_utc.with_timezone(&chrono::Local);
                self.target_end_time_str = Some(target_dt_local.to_rfc3339_opts(SecondsFormat::Secs, true));


                let now_utc = Utc::now();
                let elapsed_secs = (now_utc - st_dt).num_seconds();

                if pred_secs > 0.0 {
                    let current_progress_val = (elapsed_secs as f64 / pred_secs) * 100.0;
                    self.progress = Some(format!("{:.2}%", current_progress_val.clamp(0.0, 100.0)));
                }


                let remaining_total_secs = (target_dt_utc - now_utc).num_seconds();
                if remaining_total_secs > 0 {
                    self.remaining_time_str = Some(format_duration(remaining_total_secs));
                } else {
                    self.remaining_time_str = Some("00d:00h:00m:00s".to_string());
                     if self.progress.as_deref().unwrap_or("0") != "100.00%" && elapsed_secs > pred_secs as i64 {
                        // If time is up but progress not 100%, and it's not "completed" or "failed"
                        // This indicates it's likely finished or should be.
                        // The API itself should reflect "Completed" in task_status eventually.
                        // For now, if remaining is zero, and not explicitly other states, assume 100%
                        if self.task_status.as_deref() != Some("Completed") && self.task_status.as_deref() != Some("Failed") {
                           // self.progress = Some("100.00%".to_string()); // Or let API update status.
                        }
                    }
                }
            }
        }
    }
}

// Helper to parse flexible datetime strings to UTC DateTime<Utc>
fn parse_datetime_utc(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO 8601 with Z
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try ISO 8601 without Z (naive, assume UTC)
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(Utc.from_utc_datetime(&ndt));
    }
    // Try "YYYY-MM-DD HH:MM:SS" (naive, assume UTC)
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&ndt));
    }
    // Try "YYYY-MM-DD HH:MM:SS" (naive, assume local then convert to UTC)
    // This is tricky because "local" is ambiguous on server. For now, assume UTC if no tz.
    warn!("Failed to parse datetime string: {}", s);
    None
}

fn format_duration(total_seconds: i64) -> String {
    if total_seconds < 0 { return "00d:00h:00m:00s".to_string(); }
    let days = total_seconds / 86400;
    let remaining_seconds = total_seconds % 86400;
    let hours = remaining_seconds / 3600;
    let remaining_seconds = remaining_seconds % 3600;
    let minutes = remaining_seconds / 60;
    let seconds = remaining_seconds % 60;
    format!("{:02}d:{:02}h:{:02}m:{:02}s", days, hours, minutes, seconds)
}


#[derive(Deserialize, Debug)]
struct UserPrintResponseDevice {
    dev_id: Option<String>,
    dev_name: Option<String>,
    dev_online: Option<String>,
    task_status: Option<String>, // Note: this might be different from /my/tasks status
                                 // and often seems to be null or less informative
}

#[derive(Deserialize, Debug)]
struct UserPrintResponse {
    devices: Option<Vec<UserPrintResponseDevice>>,
    message: Option<String>, // For errors
    code: Option<String>, // For error codes
}

#[derive(Deserialize, Debug)]
struct MyTask {
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
    title: Option<String>,
    status: Option<i32>, // e.g., 2 for printing
    #[serde(rename = "startTime")]
    start_time: Option<String>, // ISO 8601 format like "2023-12-05T15:02:30.000Z"
    #[serde(rename = "costTime")]
    cost_time: Option<f64>, // Total print duration in seconds
}

#[derive(Deserialize, Debug)]
struct MyTasksResponse {
    hits: Option<Vec<MyTask>>,
    message: Option<String>, // For errors
    code: Option<String>, // For error codes
}

// Represents the possible outcomes of an API call more explicitly
#[derive(Debug)]
pub enum ApiError {
    Network(reqwest::Error),
    HttpError { status: reqwest::StatusCode, message: String, error_code: Option<String> }, // Specific HTTP error code from Bambu
    Deserialization(serde_json::Error),
    AuthError(String), // Specific for 401 or token issues
    Generic(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::Network(err)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::Deserialization(err)
    }
}


pub struct BambuApiClientRs {
    client: Client,
}

impl BambuApiClientRs {
    pub fn new() -> Self {
        info!("BambuApiClientRs initialized.");
        Self {
            client: Client::new(),
        }
    }

    async fn log_api_request_debug<T: Serialize + std::fmt::Debug>(
        method: &str,
        url: &str,
        headers: &HeaderMap,
        json_body: Option<&T>,
    ) {
        if log::max_level() < log::LevelFilter::Debug { return; } // Skip if debug not enabled

        let mut log_headers_map = HashMap::new();
        for (name, value) in headers.iter() {
            let value_str = value.to_str().unwrap_or("[Non-ASCII Value]");
            log_headers_map.insert(name.as_str().to_string(), value_str.to_string());
        }
        if log_headers_map.contains_key(AUTHORIZATION.as_str()) {
            log_headers_map.insert(AUTHORIZATION.as_str().to_string(), "[REDACTED]".to_string());
        }

        log::debug!("API Request: {} {}", method, url);
        log::debug!("API Headers: {:?}", log_headers_map);
        if let Some(body) = json_body {
            match serde_json::to_string_pretty(body) {
                Ok(pretty_body) => log::debug!("API Request Body:\n{}", pretty_body),
                Err(_) => log::debug!("API Request Body (raw): {:?}", body),
            }
        }
    }

    async fn log_api_response_debug(response_status: reqwest::StatusCode, response_headers: &HeaderMap, text_body: &str) {
        if log::max_level() < log::LevelFilter::Debug { return; }

        log::debug!("API Response Status: {}", response_status);
        let mut log_headers_map = HashMap::new(); // Using imported HashMap
         for (name, value) in response_headers.iter() {
            log_headers_map.insert(name.as_str().to_string(), value.to_str().unwrap_or("[REDACTED]").to_string());
        }
        log::debug!("API Response Headers: {:?}", log_headers_map);

        match serde_json::from_str::<serde_json::Value>(text_body) {
            Ok(json_val) => match serde_json::to_string_pretty(&json_val) {
                Ok(pretty_json) => log::debug!("API Response Body:\n{}", pretty_json),
                Err(_) => log::debug!("API Response Body (raw text, pretty print failed): {}", text_body),
            },
            Err(_) => log::debug!("API Response Body (not JSON): {}", text_body),
        }
    }

    async fn make_request_base<T: Serialize + std::fmt::Debug, R: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        json_body: Option<&T>,
        access_token: Option<&str>,
        is_login: bool, // To prevent token clearing on login failure
    ) -> Result<R, ApiError> {
        let url = format!("{}{}", API_BASE_URL, endpoint);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(token) = access_token {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| ApiError::Generic(format!("Invalid token format: {}", e)))?);
        }

        Self::log_api_request_debug(method.as_str(), &url, &headers, json_body).await;

        let mut request_builder = self.client.request(method, &url).headers(headers);
        if let Some(body) = json_body {
            request_builder = request_builder.json(body);
        }

        let response = request_builder.send().await?;
        let response_status = response.status();
        let response_headers = response.headers().clone();
        let text_body = response.text().await?;

        Self::log_api_response_debug(response_status, &response_headers, &text_body).await;

        if response_status.is_success() {
            serde_json::from_str(&text_body).map_err(ApiError::from)
        } else {
            // Try to parse as LoginResponse or a generic error structure to get message/code
            let (api_message, api_code) = match serde_json::from_str::<LoginResponse>(&text_body) {
                Ok(err_resp) => (err_resp.message.unwrap_or_else(|| text_body.clone()), err_resp.code),
                Err(_) => (text_body.clone(), None)
            };

            if response_status == reqwest::StatusCode::UNAUTHORIZED && !is_login {
                 log::error!("API call unauthorized (401) for endpoint: {}. Token might be invalid.", endpoint);
                 // The caller should handle token clearing based on this error type
                 Err(ApiError::AuthError(api_message))
            } else {
                log::error!("API call failed for {}: {} - {}", endpoint, response_status, api_message);
                Err(ApiError::HttpError{status: response_status, message: api_message, error_code: api_code})
            }
        }
    }


    pub async fn login<'a>(&self, email: &'a str, password: &'a str) -> Result<LoginResponse, ApiError> {
        info!("Attempting login for email: {}", email);
        let payload = LoginRequest { account: email, password };
        self.make_request_base(reqwest::Method::POST, "/v1/user-service/user/login", Some(&payload), None, true).await
    }

    pub async fn login_2fa<'a>(&self, email: &'a str, code: &'a str) -> Result<LoginResponse, ApiError> {
        info!("Attempting 2FA login for email: {}", email);
        let payload = Login2FARequest { account: email, code };
        self.make_request_base(reqwest::Method::POST, "/v1/user-service/user/login", Some(&payload), None, true).await
    }

    fn map_task_status_code(code: Option<i32>) -> String {
        match code {
            Some(0) => "Preparing".to_string(), // Example, adjust based on actual API
            Some(1) => "Slicing".to_string(),
            Some(2) => "Printing".to_string(),
            Some(3) => "Paused".to_string(),
            Some(4) => "Completed".to_string(),
            Some(5) => "Failed".to_string(),
            Some(6) => "Cancelling".to_string(),
            Some(7) => "Cancelled".to_string(),
            _ => "N/A".to_string(),
        }
    }

    pub async fn get_printer_status(&self, serial_number: &str, access_token: &str) -> Result<DeviceStatus, ApiError> {
        info!("Fetching printer status for serial: {}", serial_number);

        // 1. Get initial device status from /api/user/print
        let initial_status_response: UserPrintResponse = self.make_request_base(
            reqwest::Method::GET,
            "/v1/iot-service/api/user/print?force=true", // Added force=true as per Python
            None::<&String>, // No body
            Some(access_token),
            false
        ).await?;

        let mut base_status = DeviceStatus::default();
        let mut device_found_in_user_print = false;

        if let Some(devices) = initial_status_response.devices {
            if let Some(dev_info) = devices.iter().find(|d| d.dev_id.as_deref() == Some(serial_number)) {
                base_status.dev_id = dev_info.dev_id.clone();
                base_status.dev_name = dev_info.dev_name.clone();
                base_status.dev_online = dev_info.dev_online.clone();
                // task_status from /api/user/print is often null or not detailed.
                // We'll try to overwrite with /my/tasks if online.
                base_status.task_status = dev_info.task_status.clone();
                device_found_in_user_print = true;
            }
        }

        if !device_found_in_user_print {
            warn!("Device {} not found in /api/user/print response.", serial_number);
            // If error in initial_status_response itself, return that
            if initial_status_response.message.is_some() || initial_status_response.code.is_some() {
                 return Err(ApiError::Generic(format!("Error from /api/user/print: {} (Code: {:?})",
                    initial_status_response.message.unwrap_or_default(), initial_status_response.code)));
            }
            // Otherwise, device just not listed
            return Err(ApiError::Generic(format!("Device {} not found in user's bound devices.", serial_number)));
        }


        // 2. If online, augment with /my/tasks
        if base_status.is_online() {
            info!("Device {} is online, fetching detailed tasks.", serial_number);
            let tasks_endpoint = format!("/v1/user-service/my/tasks?deviceId={}", serial_number);
            let tasks_response: MyTasksResponse = self.make_request_base(
                reqwest::Method::GET,
                &tasks_endpoint,
                None::<&String>,
                Some(access_token),
                false
            ).await?;

            if let Some(tasks) = tasks_response.hits {
                // Find the most relevant active task (status == 2 is often "printing")
                if let Some(active_task) = tasks.iter().find(|t| t.status == Some(2) && t.device_id.as_deref() == Some(serial_number)) {
                    info!("Found active task: {:?}", active_task.title);
                    base_status.task_name = active_task.title.clone();
                    base_status.task_status = Some(Self::map_task_status_code(active_task.status));
                    base_status.start_time = active_task.start_time.clone();
                    base_status.prediction = active_task.cost_time.map(|ct| ct.to_string());
                    // Progress is often not directly in /my/tasks, will be calculated if start_time and prediction available
                } else {
                    info!("No active (status 2) task found for {} in /my/tasks. Using initial status.", serial_number);
                }
            } else if tasks_response.message.is_some() || tasks_response.code.is_some() {
                 warn!("Error fetching /my/tasks for {}: {} (Code: {:?}). Using initial status only.",
                    serial_number, tasks_response.message.unwrap_or_default(), tasks_response.code);
            }
        } else {
            info!("Device {} is offline. Returning status from /api/user/print.", serial_number);
        }

        base_status.calculate_derived_fields(); // Calculate progress, remaining time etc.
        Ok(base_status)
    }
}

impl Default for BambuApiClientRs {
    fn default() -> Self {
        Self::new()
    }
}
