//! Enrollment + session-check endpoints: `/greet`, `/sign-up`, `/sign-in`, `/verify`.
//!
//! Flow (see `docs/protocol-notes.md` §Endpoints and the backend's `CLIENT.md`):
//! 1. [`greet`] sends our public key, returns the server's public key.
//! 2. The caller derives the shared key and seals the user name + ehlo.
//! 3. [`sign_up`] (new account) or [`sign_in`] (existing account) submits the
//!    sealed credentials and returns the server-issued device token to persist
//!    (`is_confirmed=false` after — admin approval pending).
//! 4. [`verify`] polls until an admin approves (401 → not yet; 200 → approved).

use super::client::{check_status, ApiClient, DEVICE_TOKEN_HEADER};
use super::error::ApiError;
use super::models::{
    GreetRequest, GreetResponse, ReSignRequest, RefreshRequest, RefreshResponse, SignRequest,
    SignResponse,
};

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

/// `POST /sign-up` — create a new account from the sealed name + ehlo and link
/// this device to it, returning the server-issued device token.
///
/// Returns [`ApiError::Conflict`] (409) if the name is already taken — the caller
/// should fall back to [`sign_in`] or pick another name. On success the device
/// exists but is unconfirmed; poll [`verify`] until an admin approves it. Both
/// args are `hex(seal(..))`.
pub async fn sign_up(
    client: &ApiClient,
    sealed_name_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<String, ApiError> {
    sign(client, "/sign-up", sealed_name_hex, sealed_ehlo_hex).await
}

/// `POST /sign-in` — link this device to an existing account by sealed name +
/// ehlo, returning the server-issued device token.
///
/// Returns [`ApiError::Unauthorized`] (401) for an unknown name, a wrong ehlo, or
/// a soft-deleted account (deliberately indistinguishable). On success the device
/// exists but is unconfirmed; poll [`verify`] until an admin approves it. Both
/// args are `hex(seal(..))`.
pub async fn sign_in(
    client: &ApiClient,
    sealed_name_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<String, ApiError> {
    sign(client, "/sign-in", sealed_name_hex, sealed_ehlo_hex).await
}

/// Shared body for [`sign_up`]/[`sign_in`] — identical payload + response, only
/// the path and the meaning of a non-2xx status differ (handled by the callers).
async fn sign(
    client: &ApiClient,
    path: &str,
    sealed_name_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<String, ApiError> {
    let body = SignRequest {
        name: sealed_name_hex.to_string(),
        ehlo: sealed_ehlo_hex.to_string(),
    };
    let resp = client
        .http()
        .post(client.url(path))
        .json(&body)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    let parsed: SignResponse = resp.json().await?;
    Ok(parsed.token)
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

/// `POST /re-sign` — re-bind this identity to the caller's current source IP.
///
/// Use as the fallback when [`verify`] returns 401 because the IP changed.
/// `token_hex` is `hex(device_token_bytes)` (plain, **not** sealed); `sealed_ehlo_hex`
/// is `hex(seal(ehlo))`. On success the server resets `is_confirmed=false`, so an
/// admin must re-approve before [`verify`] passes again.
pub async fn re_sign(
    client: &ApiClient,
    token_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<(), ApiError> {
    let body = ReSignRequest {
        token: token_hex.to_string(),
        ehlo: sealed_ehlo_hex.to_string(),
    };
    let resp = client
        .http()
        .post(client.url("/re-sign"))
        .json(&body)
        .send()
        .await?;
    check_status(resp).await?;
    Ok(())
}

/// `POST /refresh` — rotate the device token, returning the new raw token.
///
/// Looked up by source IP (no `device-token` header) and **keeps** confirmation, so
/// unlike [`re_sign`] no admin re-approval is needed — but the caller must be at the
/// registered IP. Both args are `hex(seal(..))`. Persist the returned token: the old
/// one is now invalid.
pub async fn refresh(
    client: &ApiClient,
    sealed_token_hex: &str,
    sealed_ehlo_hex: &str,
) -> Result<String, ApiError> {
    let body = RefreshRequest {
        token: sealed_token_hex.to_string(),
        ehlo: sealed_ehlo_hex.to_string(),
    };
    let resp = client
        .http()
        .post(client.url("/refresh"))
        .json(&body)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    let parsed: RefreshResponse = resp.json().await?;
    Ok(parsed.token)
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
