//! Encrypted local credential store under `PWM_DATA_DIR` (default `~/.pwd-manager`).
//!
//! Holds the long-lived secrets established at enrollment — the X25519 keypair, the
//! server's public key, the device token, and the ehlo secret — so they survive
//! restarts without ever sitting in plaintext on disk.
//!
//! At rest the file is:
//!
//! ```text
//! "PWMS" (4) ‖ version (1) ‖ salt (16) ‖ seal(json, key)      where
//!   key  = Argon2id(passphrase, salt) → 32 bytes
//!   seal = nonce(12) ‖ ciphertext‖tag        (see crate::crypto)
//! ```
//!
//! The master passphrase is never stored; an attacker with the file still needs it
//! (and Argon2id's cost) to recover anything. We chose passphrase-encryption over an
//! OS keyring because the target runs headless, where no Secret Service is available.

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::Config;
use crate::crypto::{self, CryptoError};

/// Magic bytes identifying our store file format.
const MAGIC: &[u8; 4] = b"PWMS";
/// On-disk format version (bump when the layout changes).
///
/// v2 added `user_name` to [`StoreState`] for the user sign-up/sign-in model; a v1
/// store (from the old `/register` flow) is rejected as unsupported → re-enroll.
const VERSION: u8 = 2;
/// Argon2 salt length in bytes.
const SALT_LEN: usize = 16;
/// File name within the data directory.
const STORE_FILE: &str = "store.enc";

/// The persistent secret state, (de)serialized as the store payload.
///
/// All fields are secret. Deriving [`ZeroizeOnDrop`] wipes them from memory when the
/// value is dropped. We deliberately do *not* derive `Debug`/`PartialEq` so secrets
/// can't be logged or compared in non-constant time by accident.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoreState {
    /// X25519 private key (clamped). Never leaves this machine.
    pub client_private: [u8; 32],
    /// X25519 public key, sent at `/greet`.
    pub client_public: [u8; 32],
    /// Server's X25519 public key, from the `/greet` response.
    pub server_public: [u8; 32],
    /// The account handle (user name) used at `/sign-up` / `/sign-in`.
    pub user_name: String,
    /// Raw device token, server-issued at `/sign-up` / `/sign-in` (and rotated by
    /// `/refresh`), sent in the `device-token` header.
    pub device_token: String,
    /// The user's ehlo secret, chosen at sign-up; needed for `/re-sign` and
    /// `/refresh` and to re-`/sign-in` a new device for the same account.
    pub ehlo_secret: String,
}

impl StoreState {
    /// Re-derive the ECDH shared key (raw 32-byte AES-256 key) from the stored
    /// private key and server public key. Not persisted — cheap to recompute.
    pub fn shared_key(&self) -> [u8; 32] {
        crypto::derive_shared_key(&self.client_private, &self.server_public)
    }
}

/// Errors from loading or saving the local store.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// No store file exists yet (first run → enroll).
    #[error("no local store found at {0}")]
    NotFound(String),
    /// Decryption failed — wrong passphrase or tampered file.
    #[error("wrong passphrase, or the store file is corrupt")]
    WrongPassphrase,
    /// The file exists but isn't a valid store.
    #[error("store file is corrupt: {0}")]
    Corrupt(String),
    /// File written by a newer/unknown format version.
    #[error("unsupported store version: {0} (this build supports {VERSION})")]
    UnsupportedVersion(u8),
    /// Argon2id key derivation failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// Payload (de)serialization failed.
    #[error("store (de)serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handle to the local store at a resolved path.
#[derive(Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// Resolve the store path from config (expanding a leading `~`).
    pub fn new(config: &Config) -> Self {
        Self {
            path: expand_tilde(&config.data_dir).join(STORE_FILE),
        }
    }

    /// The resolved store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a store file already exists (i.e. this machine is enrolled).
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Encrypt `state` under `passphrase` and write it atomically with `0600` perms.
    pub fn save(&self, state: &StoreState, passphrase: &str) -> Result<(), StoreError> {
        let mut json = serde_json::to_vec(state)?;

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut key = derive_key(passphrase, &salt)?;
        let sealed = crypto::seal(&json, &key);
        json.zeroize();
        key.zeroize();

        let mut out = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + sealed.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&sealed);

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            set_dir_private(parent);
        }
        write_private(&self.path, &out)
    }

    /// Read and decrypt the store with `passphrase`.
    pub fn load(&self, passphrase: &str) -> Result<StoreState, StoreError> {
        let raw = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(self.path.display().to_string()));
            }
            Err(e) => return Err(StoreError::Io(e)),
        };

        let header = MAGIC.len() + 1 + SALT_LEN;
        if raw.len() < header {
            return Err(StoreError::Corrupt("file shorter than header".into()));
        }
        if &raw[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Corrupt("bad magic bytes".into()));
        }
        let version = raw[MAGIC.len()];
        if version != VERSION {
            return Err(StoreError::UnsupportedVersion(version));
        }
        let salt = &raw[MAGIC.len() + 1..header];
        let sealed = &raw[header..];

        let mut key = derive_key(passphrase, salt)?;
        let opened = crypto::open(sealed, &key).map_err(|e| match e {
            CryptoError::Decrypt => StoreError::WrongPassphrase,
            other => StoreError::Corrupt(other.to_string()),
        });
        key.zeroize();
        let mut json = opened?;

        let state = serde_json::from_slice(&json)?;
        json.zeroize();
        Ok(state)
    }
}

/// Derive a 32-byte key from `passphrase` and `salt` using Argon2id (defaults).
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], StoreError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| StoreError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Write `data` to `path` atomically (temp file + rename) with `0600` permissions.
fn write_private(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let tmp = path.with_extension("tmp");

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);

    fs::rename(&tmp, path)?;
    Ok(())
}

/// Best-effort tighten of the data directory to `0700` (unix only).
fn set_dir_private(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Expand a leading `~`/`~/` to the user's home directory; otherwise return the
/// path unchanged.
fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_with(path, home_dir())
}

/// The user's home directory: `$HOME` (Unix/macOS), falling back to
/// `%USERPROFILE%` on Windows, where `HOME` is usually unset. Without this
/// fallback the default `~/.pwd-manager` would land in a literal `~` folder under
/// the launch directory on a stock Windows session.
fn home_dir() -> Option<OsString> {
    resolve_home(std::env::var_os("HOME"), std::env::var_os("USERPROFILE"))
}

/// Pure resolver for [`home_dir`] (kept env-free so it is unit-testable): prefer a
/// non-empty `HOME`, else a non-empty `USERPROFILE`.
fn resolve_home(
    home: Option<impl AsRef<OsStr>>,
    userprofile: Option<impl AsRef<OsStr>>,
) -> Option<OsString> {
    if let Some(home) = home {
        if !home.as_ref().is_empty() {
            return Some(home.as_ref().to_os_string());
        }
    }
    userprofile
        .filter(|u| !u.as_ref().is_empty())
        .map(|u| u.as_ref().to_os_string())
}

/// Pure core of [`expand_tilde`]: expand `~`/`~/` against `home` when present,
/// otherwise (no home resolvable) return the path unchanged rather than guessing.
fn expand_tilde_with(path: &str, home: Option<OsString>) -> PathBuf {
    if path == "~" {
        if let Some(home) = home {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> StoreState {
        StoreState {
            client_private: [1u8; 32],
            client_public: [2u8; 32],
            server_public: [3u8; 32],
            user_name: "alice".into(),
            device_token: "device-token-001".into(),
            ehlo_secret: "ehlo-secret-xyz".into(),
        }
    }

    fn assert_state_eq(a: &StoreState, b: &StoreState) {
        assert_eq!(a.client_private, b.client_private);
        assert_eq!(a.client_public, b.client_public);
        assert_eq!(a.server_public, b.server_public);
        assert_eq!(a.user_name, b.user_name);
        assert_eq!(a.device_token, b.device_token);
        assert_eq!(a.ehlo_secret, b.ehlo_secret);
    }

    fn config_in(dir: &Path) -> Config {
        Config {
            api_base_url: "http://localhost:53971".into(),
            request_timeout_secs: 30,
            verify_tls: true,
            data_dir: dir.to_string_lossy().into_owned(),
            clipboard_clear_secs: 30,
            idle_lock_secs: 300,
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        let state = sample_state();

        assert!(!store.exists());
        store.save(&state, "correct horse battery staple").unwrap();
        assert!(store.exists());

        let loaded = store.load("correct horse battery staple").unwrap();
        assert_state_eq(&state, &loaded);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        store.save(&sample_state(), "right").unwrap();

        assert!(matches!(
            store.load("wrong"),
            Err(StoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn load_missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        assert!(matches!(store.load("x"), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn corrupt_magic_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        fs::write(store.path(), b"not a real store file at all").unwrap();
        assert!(matches!(store.load("x"), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn shared_key_matches_crypto_derivation() {
        let state = sample_state();
        let expected = crypto::derive_shared_key(&state.client_private, &state.server_public);
        assert_eq!(state.shared_key(), expected);
    }

    #[cfg(unix)]
    #[test]
    fn store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        store.save(&sample_state(), "pw").unwrap();
        let mode = fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn expand_tilde_resolves_home() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(
            expand_tilde("~/.pwd-manager"),
            PathBuf::from("/home/tester/.pwd-manager")
        );
        assert_eq!(expand_tilde("~"), PathBuf::from("/home/tester"));
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
    }

    #[test]
    fn resolve_home_prefers_home_then_userprofile() {
        // HOME wins outright when set (Unix/macOS).
        assert_eq!(
            resolve_home(Some("/home/a"), Some("C:\\Users\\a")),
            Some(OsString::from("/home/a"))
        );
        // Empty HOME falls through to USERPROFILE (the Windows case).
        assert_eq!(
            resolve_home(Some(""), Some("C:\\Users\\a")),
            Some(OsString::from("C:\\Users\\a"))
        );
        // Neither set → no home.
        assert_eq!(resolve_home(None::<&str>, None::<&str>), None);
    }

    #[test]
    fn expand_tilde_with_uses_home_or_leaves_path() {
        // A `~/` path joins onto the resolved home (e.g. from USERPROFILE).
        assert_eq!(
            expand_tilde_with("~/.pwd-manager", Some(OsString::from("/home/x"))),
            PathBuf::from("/home/x/.pwd-manager")
        );
        assert_eq!(
            expand_tilde_with("~", Some(OsString::from("/home/x"))),
            PathBuf::from("/home/x")
        );
        // With no home resolvable, the `~` path is returned unchanged, not guessed.
        assert_eq!(
            expand_tilde_with("~/.pwd-manager", None),
            PathBuf::from("~/.pwd-manager")
        );
        // A non-`~` path is always returned verbatim.
        assert_eq!(
            expand_tilde_with("/abs/path", Some(OsString::from("/home/x"))),
            PathBuf::from("/abs/path")
        );
    }
}
