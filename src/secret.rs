//! The decrypted contents of a password entry — the plaintext we seal into the
//! server's opaque `pwd` field.
//!
//! The backend stores `pwd` as opaque bytes; **we** define the JSON shape
//! (`docs/protocol-notes.md` §pwd-plaintext). Everything here is secret: the type
//! zeroizes on drop and deliberately has no `Debug`. Server-side `name`/`extra` are
//! plaintext and must never carry these values.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto;

/// The plaintext of one entry. Fields default to empty so older/partial blobs and
/// future additions deserialize cleanly.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PwdSecret {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
}

/// Errors sealing or opening a [`PwdSecret`].
#[derive(thiserror::Error, Debug)]
pub enum SecretError {
    /// AES-GCM open failed — wrong key or corrupt/garbled ciphertext.
    #[error("could not decrypt entry (wrong key or corrupt data)")]
    Decrypt,
    /// The decrypted bytes were not the JSON we expect.
    #[error("decrypted entry was not valid JSON: {0}")]
    Decode(String),
    /// Serializing the secret to JSON failed (shouldn't happen for these fields).
    #[error("could not encode entry: {0}")]
    Encode(String),
}

impl PwdSecret {
    /// Serialize to JSON and seal under `key`, returning `hex(nonce‖ct‖tag)` —
    /// the form the server stores in `pwd`.
    pub fn seal(&self, key: &[u8; 32]) -> Result<String, SecretError> {
        let mut json = serde_json::to_vec(self).map_err(|e| SecretError::Encode(e.to_string()))?;
        let hex = crypto::seal_hex(&json, key);
        json.zeroize();
        Ok(hex)
    }

    /// Decode `hex(nonce‖ct‖tag)`, open under `key`, and parse the JSON.
    pub fn open(hex_blob: &str, key: &[u8; 32]) -> Result<Self, SecretError> {
        let mut bytes = crypto::open_hex(hex_blob, key).map_err(|_| SecretError::Decrypt)?;
        let secret = serde_json::from_slice(&bytes).map_err(|e| SecretError::Decode(e.to_string()));
        bytes.zeroize();
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PwdSecret {
        PwdSecret {
            username: "alice".into(),
            password: "s3cr3t".into(),
            url: "https://example.com".into(),
            notes: "recovery: bob@example.com".into(),
        }
    }

    fn key() -> [u8; 32] {
        crypto::derive_shared_key(
            &crypto::generate_keypair().private,
            &crypto::generate_keypair().public,
        )
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let k = key();
        let s = sample();
        let sealed = s.seal(&k).unwrap();
        let opened = PwdSecret::open(&sealed, &k).unwrap();
        assert_eq!(opened.username, "alice");
        assert_eq!(opened.password, "s3cr3t");
        assert_eq!(opened.url, "https://example.com");
        assert_eq!(opened.notes, "recovery: bob@example.com");
    }

    #[test]
    fn open_with_wrong_key_is_decrypt_error() {
        let sealed = sample().seal(&[1u8; 32]).unwrap();
        assert!(matches!(
            PwdSecret::open(&sealed, &[2u8; 32]),
            Err(SecretError::Decrypt)
        ));
    }

    #[test]
    fn missing_fields_default_to_empty() {
        let k = key();
        // A blob that only carried a password (e.g. a future-trimmed entry).
        let sealed = crypto::seal_hex(br#"{"password":"x"}"#, &k);
        let opened = PwdSecret::open(&sealed, &k).unwrap();
        assert_eq!(opened.password, "x");
        assert!(opened.username.is_empty());
        assert!(opened.url.is_empty());
    }
}
