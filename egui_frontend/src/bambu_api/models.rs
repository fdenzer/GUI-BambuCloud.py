use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// --- Request Structs ---
#[derive(Serialize, Debug)]
pub struct LoginRequest<'a> {
    pub account: &'a str,
    pub password: &'a str,
}

#[derive(Serialize, Debug)]
pub struct Login2FARequest<'a> {
    pub account: &'a str,
    pub code: &'a str,
}

// --- Response Structs ---
#[derive(Deserialize, Debug, Clone)]
pub struct LoginResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "loginType")]
    pub login_type: Option<String>,
    pub message: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct DeviceStatus {
    pub dev_id: Option<String>,
    pub dev_name: Option<String>,
    #[serde(deserialize_with = "crate::bambu_api::utils::string_or_int")]
    pub dev_online: Option<String>,
    pub task_name: Option<String>,
    pub task_status: Option<String>,
    #[serde(deserialize_with = "crate::bambu_api::utils::string_or_int")]
    pub progress: Option<String>,
    pub start_time: Option<String>,
    #[serde(deserialize_with = "crate::bambu_api::utils::string_or_int")]
    pub prediction: Option<String>,
    #[serde(skip)]
    pub target_end_time_str: Option<String>,
    #[serde(skip)]
    pub remaining_time_str: Option<String>,
    #[serde(skip)]
    pub total_duration_str: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct UserPrintResponseDevice {
    pub dev_id: Option<String>,
    pub dev_name: Option<String>,
    pub dev_online: Option<String>,
    pub task_status: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct UserPrintResponse {
    pub devices: Option<Vec<UserPrintResponseDevice>>,
    pub message: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct MyTask {
    #[serde(rename = "deviceId")]
    pub device_id: Option<String>,
    pub title: Option<String>,
    pub status: Option<i32>,
    #[serde(rename = "startTime")]
    pub start_time: Option<String>,
    #[serde(rename = "costTime")]
    pub cost_time: Option<f64>,
}

#[derive(Deserialize, Debug)]
pub struct MyTasksResponse {
    pub hits: Option<Vec<MyTask>>,
    pub message: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug)]
pub enum ApiError {
    AuthError(String),
    Generic(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(_err: reqwest::Error) -> Self {
        ApiError::Generic("Network error".to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_err: serde_json::Error) -> Self {
        ApiError::Generic("Deserialization error".to_string())
    }
}
