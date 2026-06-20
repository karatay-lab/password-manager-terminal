use std::env;
use std::str::FromStr;

/// Runtime configuration, sourced from the environment (`.env`) with sane defaults.
///
/// Precedence for v1 is env > defaults; CLI/file layers come later (see plan §7).
#[derive(Clone, Debug)]
pub struct Config {
    /// Backend API base URL, no trailing slash.
    pub api_base_url: String,
    /// HTTP request timeout.
    pub request_timeout_secs: u64,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// Directory holding the encrypted local credential/state store.
    pub data_dir: String,
    /// Seconds after which copied secrets are wiped from the clipboard.
    pub clipboard_clear_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            api_base_url: env::var("PWM_API_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:53971".to_string()),
            request_timeout_secs: parse_env("PWM_REQUEST_TIMEOUT_SECS", 30),
            verify_tls: parse_env("PWM_VERIFY_TLS", true),
            data_dir: env::var("PWM_DATA_DIR").unwrap_or_else(|_| "~/.pwd-manager".to_string()),
            clipboard_clear_secs: parse_env("PWM_CLIPBOARD_CLEAR_SECS", 30),
        }
    }
}

/// Parse an env var into `T`, falling back to `default` when unset or invalid.
fn parse_env<T: FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
