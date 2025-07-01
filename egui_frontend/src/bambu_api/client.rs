use reqwest::{Client, header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE}};
use serde::Serialize;
use chrono::Local;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use log::{info, warn};

use crate::bambu_api::models::*;
use crate::bambu_api::utils::*;

const API_BASE_URL: &str = "https://api.bambulab.com";

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
        let mut log_headers_map = HashMap::new();
        for (name, value) in headers.iter() {
            let value_str = value.to_str().unwrap_or("[Non-ASCII Value]");
            log_headers_map.insert(name.as_str().to_string(), value_str.to_string());
        }
        if log_headers_map.contains_key(AUTHORIZATION.as_str()) {
            log_headers_map.insert(AUTHORIZATION.as_str().to_string(), "[REDACTED]".to_string());
        }

        let mut msg = format!("API Request: {} {}\nAPI Headers: {:?}", method, url, log_headers_map);
        if let Some(body) = json_body {
            match serde_json::to_string_pretty(body) {
                Ok(pretty_body) => msg.push_str(&format!("\nAPI Request Body:\n{}", pretty_body)),
                Err(_) => msg.push_str(&format!("\nAPI Request Body (raw): {:?}", body)),
            }
        }
        Self::log_to_file(&msg);
    }

    fn log_to_file(msg: &str) {
        let now = Local::now();
        let filename = format!("bambu_api_log_{}.txt", now.format("%Y%m%d"));
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&filename) {
            let _ = writeln!(file, "{}: {}", now.format("%Y-%m-%d %H:%M:%S"), msg);
        }
    }

    async fn log_api_response_debug(response_status: reqwest::StatusCode, response_headers: &HeaderMap, text_body: &str) {
        let mut log_headers_map = HashMap::new();
        for (name, value) in response_headers.iter() {
            log_headers_map.insert(name.as_str().to_string(), value.to_str().unwrap_or("[REDACTED]").to_string());
        }
        let mut msg = format!("API Response Status: {}\nHeaders: {:?}", response_status, log_headers_map);
        match serde_json::from_str::<serde_json::Value>(text_body) {
            Ok(json_val) => match serde_json::to_string_pretty(&json_val) {
                Ok(pretty_json) => msg.push_str(&format!("\nAPI Response Body:\n{}", pretty_json)),
                Err(_) => msg.push_str(&format!("\nAPI Response Body (raw text, pretty print failed): {}", text_body)),
            },
            Err(_) => msg.push_str(&format!("\nAPI Response Body (not JSON): {}", text_body)),
        }
        Self::log_to_file(&msg);
    }

    async fn make_request_base<T: Serialize + std::fmt::Debug, R: for<'de> serde::Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        json_body: Option<&T>,
        access_token: Option<&str>,
        is_login: bool,
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
            let (api_message, api_code) = match serde_json::from_str::<LoginResponse>(&text_body) {
                Ok(err_resp) => (err_resp.message.unwrap_or_else(|| text_body.clone()), err_resp.code),
                Err(_) => (text_body.clone(), None)
            };

            if response_status == reqwest::StatusCode::UNAUTHORIZED && !is_login {
                 log::error!("API call unauthorized (401) for endpoint: {}. Token might be invalid.", endpoint);
                 Err(ApiError::AuthError(api_message))
            } else {
                log::error!("API call failed for {}: {} - {}", endpoint, response_status, api_message);
                Err(ApiError::Generic(format!("HTTP error {}: {}", response_status, api_message)))
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
            Some(0) => "Preparing".to_string(),
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
        let initial_status_response: UserPrintResponse = self.make_request_base(
            reqwest::Method::GET,
            "/v1/iot-service/api/user/print?force=true",
            None::<&String>,
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
                base_status.task_status = dev_info.task_status.clone();
                device_found_in_user_print = true;
            }
        }

        if !device_found_in_user_print {
            warn!("Device {} not found in /api/user/print response.", serial_number);
            if initial_status_response.message.is_some() || initial_status_response.code.is_some() {
                 return Err(ApiError::Generic(format!("Error from /api/user/print: {} (Code: {:?})",
                    initial_status_response.message.unwrap_or_default(), initial_status_response.code)));
            }
            return Err(ApiError::Generic(format!("Device {} not found in user's bound devices.", serial_number)));
        }

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
                if let Some(active_task) = tasks.iter().find(|t| t.status == Some(2) && t.device_id.as_deref() == Some(serial_number)) {
                    info!("Found active task: {:?}", active_task.title);
                    base_status.task_name = active_task.title.clone();
                    base_status.task_status = Some(Self::map_task_status_code(active_task.status));
                    base_status.start_time = active_task.start_time.clone();
                    base_status.prediction = active_task.cost_time.map(|ct| ct.to_string());
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

        base_status.calculate_derived_fields();
        Ok(base_status)
    }
}

impl Default for BambuApiClientRs {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceStatus {
    pub fn is_online(&self) -> bool {
        self.dev_online.as_deref().unwrap_or("false").to_lowercase() == "true"
    }

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
                self.target_end_time_str = Some(target_dt_local.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

                let now_utc = chrono::Utc::now();
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
                        if self.task_status.as_deref() != Some("Completed") && self.task_status.as_deref() != Some("Failed") {
                        }
                    }
                }
            }
        }
    }
}
