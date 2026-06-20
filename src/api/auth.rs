//! Enrollment + session-check endpoints: `/greet`, `/register`, `/verify`.
//!
//! Flow (see `docs/protocol-notes.md` §Endpoints and `v1/plan.md` §4):
//! 1. [`greet`] sends our public key, returns the server's public key.
//! 2. The caller derives the shared key and seals the token + ehlo.
//! 3. [`register`] submits the sealed credentials (`is_confirmed=false` after).
//! 4. [`verify`] polls until an admin approves (401 → not yet; 200 → approved).

use super::client::{check_status, ApiClient, DEVICE_TOKEN_HEADER};
use super::error::ApiError;
use super::models::{GreetRequest, GreetResponse, RegisterRequest};

/// `POST /greet` — send our X25519 public key, return the server's public key.
///
/// Returns [`ApiError::IdentityExists`] (412) if this source IP already enrolled.
pub async fn greet(client: &ApiClient, client_public: &[u8; 32]) -> Result<[u8; 32], ApiError> {
    let body = GreetRequest {
        pub_key: hex::encode(client_public),
    };
    let resp = client
        .http()
        .post(client.url("/greet"))
        .json(&body)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    let parsed: GreetResponse = resp.json().await?;
    decode_public_key(&parsed.server_public_key)
}

/// `POST /register` — submit the sealed device token and ehlo secret.
///
/// On success the identity exists but is unconfirmed; nothing else works until an
/// admin approves it (poll with [`verify`]). Both args are `hex(seal(..))`.
pub async fn register(
    client: &ApiClient,
    sealed_token_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<(), ApiError> {
    let body = RegisterRequest {
        token: sealed_token_hex.to_string(),
        ehlo: sealed_ehlo_hex.to_string(),
    };
    let resp = client
        .http()
        .post(client.url("/register"))
        .json(&body)
        .send()
        .await?;
    check_status(resp).await?;
    Ok(())
}

/// `GET /verify` — check whether the device token is currently authorized.
///
/// `Ok(())` means approved and usable. [`ApiError::Unauthorized`] (401) is the
/// expected "not approved yet / wrong IP" signal the approval-poll loops on.
pub async fn verify(client: &ApiClient, device_token: &str) -> Result<(), ApiError> {
    let resp = client
        .http()
        .get(client.url("/verify"))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .send()
        .await?;
    check_status(resp).await?;
    Ok(())
}

/// Decode a hex server public key into a fixed 32-byte array, with clear errors.
fn decode_public_key(hex_key: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| ApiError::Malformed(format!("server public key is not valid hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ApiError::Malformed(format!(
            "server public key is {} bytes, expected 32",
            v.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_public_key_accepts_32_bytes() {
        let key = [0xABu8; 32];
        assert_eq!(decode_public_key(&hex::encode(key)).unwrap(), key);
    }

    #[test]
    fn decode_public_key_rejects_bad_hex() {
        assert!(matches!(
            decode_public_key("nothex"),
            Err(ApiError::Malformed(_))
        ));
    }

    #[test]
    fn decode_public_key_rejects_wrong_length() {
        // 31 bytes, valid hex but too short.
        let err = decode_public_key(&hex::encode([0u8; 31])).unwrap_err();
        assert!(matches!(err, ApiError::Malformed(m) if m.contains("31")));
    }
}
