use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::str::FromStr;

/// Application identifier used for per-user / system config subdirectories.
pub const APP_DIR: &str = "pwd-manager-terminal";

/// Load `.env` layers into the process environment before [`Config::from_env`].
///
/// Sources are tried lowest-priority *last*: `dotenvy` never overrides a variable
/// that is already set, so the effective precedence is
/// `real environment > ./.env > user config > system config`. Missing files are
/// ignored. This lets a globally installed binary (e.g. from the `.deb`/`.msi`) pick
/// up config from a standard location instead of only the launch directory.
pub fn load_env_files() {
    // 1. Current directory (and parents) — the dev / local override.
    let _ = dotenvy::dotenv();

    // 2. Per-user config: $XDG_CONFIG_HOME or ~/.config (Unix), %APPDATA% (Windows).
    if let Some(dir) = user_config_dir() {
        let _ = dotenvy::from_path(dir.join(APP_DIR).join(".env"));
    }

    // 3. System-wide config (Unix); a harmless missing-file no-op elsewhere.
    let _ = dotenvy::from_path(format!("/etc/{APP_DIR}/.env"));
}

/// Base directory for per-user config, resolved from the real environment.
fn user_config_dir() -> Option<PathBuf> {
    config_dir_from(
        env::var_os("XDG_CONFIG_HOME"),
        env::var_os("HOME"),
        env::var_os("APPDATA"),
    )
}

/// Pure resolver for [`user_config_dir`] (kept env-free so it is unit-testable):
/// `$XDG_CONFIG_HOME`, else `$HOME/.config`, else Windows `%APPDATA%`.
fn config_dir_from(
    xdg: Option<impl AsRef<OsStr>>,
    home: Option<impl AsRef<OsStr>>,
    appdata: Option<impl AsRef<OsStr>>,
) -> Option<PathBuf> {
    if let Some(xdg) = xdg {
        if !xdg.as_ref().is_empty() {
            return Some(PathBuf::from(xdg.as_ref()));
        }
    }
    if let Some(home) = home {
        if !home.as_ref().is_empty() {
            return Some(PathBuf::from(home.as_ref()).join(".config"));
        }
    }
    appdata
        .filter(|a| !a.as_ref().is_empty())
        .map(|a| PathBuf::from(a.as_ref()))
}

/// Runtime configuration, sourced from the environment (`.env`) with sane defaults.
///
/// Precedence is `env > defaults`; the `.env` layers are merged into the environment
/// by [`load_env_files`] at startup.
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
    /// Seconds of inactivity after which the vault auto-locks (`0` disables it).
    pub idle_lock_secs: u64,
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
            idle_lock_secs: parse_env("PWM_IDLE_LOCK_SECS", 300),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(xdg: Option<&str>, home: Option<&str>, appdata: Option<&str>) -> Option<PathBuf> {
        config_dir_from(xdg, home, appdata)
    }

    #[test]
    fn config_dir_prefers_xdg_then_home_then_appdata() {
        // XDG wins outright.
        assert_eq!(
            resolve(Some("/x/cfg"), Some("/home/a"), Some("C:\\AppData")),
            Some(PathBuf::from("/x/cfg"))
        );
        // Empty XDG falls through to HOME/.config.
        assert_eq!(
            resolve(Some(""), Some("/home/a"), None),
            Some(PathBuf::from("/home/a/.config"))
        );
        // No XDG/HOME falls back to %APPDATA% (Windows).
        assert_eq!(
            resolve(None, None, Some("C:\\Users\\a\\AppData\\Roaming")),
            Some(PathBuf::from("C:\\Users\\a\\AppData\\Roaming"))
        );
        // Nothing set → no config dir.
        assert_eq!(resolve(None, None, None), None);
    }
}
