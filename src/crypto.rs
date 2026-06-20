//! Client-side cryptography — a faithful port of the backend's scheme so that
//! payloads round-trip exactly. See `docs/protocol-notes.md`.
//!
//! - **Key agreement:** X25519. The raw 32-byte ECDH output is used *directly* as
//!   the AES-256 key — no HKDF, no salt.
//! - **AEAD:** AES-256-GCM with a fresh random 12-byte nonce. The wire blob is
//!   `nonce (12) ‖ ciphertext‖tag`, then hex-encoded. No associated data.
//!
//! The server only ever sees ciphertext; the shared key never leaves the client.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// X25519 base point (u = 9), matching the backend.
const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Length of the AES-GCM nonce we prepend to every ciphertext.
const NONCE_LEN: usize = 12;

/// Errors from sealing/opening or key handling.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum CryptoError {
    /// Sealed blob shorter than the prepended nonce — cannot be valid.
    #[error("sealed data too short (need at least a {NONCE_LEN}-byte nonce)")]
    TooShort,
    /// AES-256-GCM authentication/decryption failed (wrong key or corrupt data).
    #[error("decryption failed: wrong key or corrupted data")]
    Decrypt,
    /// Input hex was not valid hex.
    #[error("invalid hex encoding")]
    Hex(#[from] hex::FromHexError),
}

/// An X25519 key pair. `private` is stored clamped (canonical form).
#[derive(Clone)]
pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// Generate a fresh X25519 key pair using the OS CSPRNG.
pub fn generate_keypair() -> KeyPair {
    let mut private = [0u8; 32];
    OsRng.fill_bytes(&mut private);
    // RFC 7748 scalar clamping (the backend does this explicitly too).
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::x25519(private, X25519_BASEPOINT);
    KeyPair { private, public }
}

/// Derive the shared secret via ECDH: `x25519(my_private, peer_public)`.
///
/// The raw output is the AES-256 key. Both sides compute the same value
/// (`shared(a_priv, b_pub) == shared(b_priv, a_pub)`).
pub fn derive_shared_key(my_private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*my_private, *peer_public)
}

/// Encrypt `plaintext` with AES-256-GCM under `key`, returning `nonce ‖ ct‖tag`.
///
/// Encryption with a valid 32-byte key cannot fail for in-memory payloads, so a
/// failure here is a genuine invariant violation and panics.
pub fn seal(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption is infallible for valid key + in-memory data");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a `nonce ‖ ct‖tag` blob produced by [`seal`].
pub fn open(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::TooShort);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// [`seal`] then hex-encode — the form sent on the wire (`token`, `ehlo`, `pwd`).
pub fn seal_hex(plaintext: &[u8], key: &[u8; 32]) -> String {
    hex::encode(seal(plaintext, key))
}

/// Hex-decode then [`open`] — for sealed fields received from the server.
pub fn open_hex(hex_blob: &str, key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    open(&hex::decode(hex_blob)?, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_is_symmetric() {
        let client = generate_keypair();
        let server = generate_keypair();
        let a = derive_shared_key(&client.private, &server.public);
        let b = derive_shared_key(&server.private, &client.public);
        assert_eq!(a, b);
    }

    #[test]
    fn rfc7748_known_answer() {
        // RFC 7748 §6.1 test vector. The bare x25519() clamps the scalar, so the
        // unclamped private keys below produce the published public keys + secret.
        let a_priv: [u8; 32] = hex::decode(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let b_priv: [u8; 32] = hex::decode(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let a_pub = x25519_dalek::x25519(a_priv, X25519_BASEPOINT);
        let b_pub = x25519_dalek::x25519(b_priv, X25519_BASEPOINT);
        assert_eq!(
            hex::encode(a_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex::encode(b_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let secret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex::encode(derive_shared_key(&a_priv, &b_pub)), secret);
        assert_eq!(hex::encode(derive_shared_key(&b_priv, &a_pub)), secret);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = derive_shared_key(&generate_keypair().private, &generate_keypair().public);
        let msg = b"my-super-secret-password";
        assert_eq!(open(&seal(msg, &key), &key).unwrap(), msg);
    }

    #[test]
    fn client_seals_server_opens() {
        // Mirrors the protocol: client seals with shared(client_priv, server_pub);
        // server opens with shared(server_priv, client_pub).
        let client = generate_keypair();
        let server = generate_keypair();
        let client_key = derive_shared_key(&client.private, &server.public);
        let server_key = derive_shared_key(&server.private, &client.public);
        let blob = seal(b"test-device-token-001", &client_key);
        assert_eq!(open(&blob, &server_key).unwrap(), b"test-device-token-001");
    }

    #[test]
    fn wire_layout_is_nonce_ct_tag() {
        // 12-byte nonce + len(plaintext) ciphertext + 16-byte GCM tag.
        let blob = seal(b"x", &[7u8; 32]);
        assert_eq!(blob.len(), NONCE_LEN + 1 + 16);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let blob = seal(b"secret", &[1u8; 32]);
        assert_eq!(open(&blob, &[2u8; 32]), Err(CryptoError::Decrypt));
    }

    #[test]
    fn open_too_short_fails() {
        assert_eq!(open(&[0u8; 4], &[0u8; 32]), Err(CryptoError::TooShort));
    }

    #[test]
    fn hex_roundtrip() {
        let key = derive_shared_key(&generate_keypair().private, &generate_keypair().public);
        assert_eq!(open_hex(&seal_hex(b"hello", &key), &key).unwrap(), b"hello");
    }

    #[test]
    fn open_hex_rejects_bad_hex() {
        assert!(matches!(open_hex("zz", &[0u8; 32]), Err(CryptoError::Hex(_))));
    }

    #[test]
    fn private_key_is_clamped() {
        let kp = generate_keypair();
        assert_eq!(kp.private[0] & 0b0000_0111, 0); // low 3 bits clear
        assert_eq!(kp.private[31] & 0b1100_0000, 0b0100_0000); // bit7 clear, bit6 set
    }
}
