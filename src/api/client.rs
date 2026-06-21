//! Thin async wrapper over [`reqwest::Client`], configured from [`Config`].
//!
//! Holds the base URL and shared connection pool; endpoint logic lives in the
//! sibling modules (`auth`, and later `groups`/`pwd`). Network + crypto run off
//! the UI thread, so these are all `async` and return [`ApiError`].

use std::time::Duration;

use crate::config::Config;

use super::error::{status_to_error, ApiError};

/// Header carrying the raw (unsealed) device token on authenticated endpoints.
pub const DEVICE_TOKEN_HEADER: &str = "device-token";

/// Configured HTTP client for one backend.
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    /// Build a client from [`Config`]: applies the request timeout and, when
    /// `verify_tls` is false, disables certificate verification (dev/self-signed
    /// only — never for production).
    pub fn new(config: &Config) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()?;
        Ok(Self {
            http,
            base_url: normalize_base_url(&config.api_base_url),
        })
    }

    /// The underlying reqwest client, for building requests.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Join `path` (a leading-slash path like `/greet`) onto the base URL.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Strip a single trailing slash so [`ApiClient::url`] can always prepend `/path`
/// without producing a double slash.
fn normalize_base_url(raw: &str) -> String {
    raw.trim_end_matches('/').to_string()
}

/// Return the response on 2xx; otherwise read the body and map the status to a
/// typed [`ApiError`]. Consumes `resp` on error (to read its body).
pub(crate) async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, ApiError> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(status_to_error(code, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_trailing_slash_is_stripped() {
        assert_eq!(normalize_base_url("http://h:53971/"), "http://h:53971");
        assert_eq!(normalize_base_url("http://h:53971"), "http://h:53971");
    }

    #[test]
    fn url_joins_without_double_slash() {
        let cfg = Config {
            api_base_url: "http://localhost:53971/".into(),
            request_timeout_secs: 30,
            verify_tls: true,
            data_dir: "~/.pwd-manager".into(),
            clipboard_clear_secs: 30,
            idle_lock_secs: 300,
        };
        let client = ApiClient::new(&cfg).unwrap();
        assert_eq!(client.url("/greet"), "http://localhost:53971/greet");
    }
}
