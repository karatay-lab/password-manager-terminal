//! Request/response DTOs for the enrollment endpoints.
//!
//! Shapes are taken from `docs/protocol-notes.md` (verified against backend source).
//! All sealed fields (`token`, `ehlo`) are hex strings of `nonce‖ct‖tag` produced
//! by [`crate::crypto::seal_hex`]; the server sees ciphertext only.

use serde::{Deserialize, Serialize};

/// `POST /greet` request — the client's X25519 public key, hex-encoded.
#[derive(Debug, Serialize)]
pub struct GreetRequest {
    /// `hex(client_public)`.
    pub pub_key: String,
}

/// `POST /greet` response — the server's X25519 public key, hex-encoded.
#[derive(Debug, Deserialize)]
pub struct GreetResponse {
    /// `hex(server_public)`; combine with our private key to derive the shared key.
    pub server_public_key: String,
}

/// `POST /register` request.
///
/// `token` is `hex(seal(device_token))` and `ehlo` is `hex(seal(ehlo_secret))`.
/// (Note: `/re-sign` later sends `token` as *plain* hex — see protocol-notes —
/// but at register both fields are sealed.)
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    /// Sealed device token, hex.
    pub token: String,
    /// Sealed ehlo secret, hex.
    pub ehlo: String,
}

/// `POST /re-sign` request — re-bind an existing identity to the caller's IP.
///
/// ⚠️ Unlike [`RegisterRequest`], `token` here is the **plain** hex of the raw
/// token bytes (NOT sealed); only `ehlo` is sealed. See `docs/protocol-notes.md`
/// (api.md is wrong on this). The server resets `is_confirmed=false` afterwards.
#[derive(Debug, Serialize)]
pub struct ReSignRequest {
    /// `hex(device_token_bytes)` — plain, not sealed.
    pub token: String,
    /// Sealed ehlo secret, hex.
    pub ehlo: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greet_request_serializes_to_pub_key_field() {
        let json = serde_json::to_value(GreetRequest {
            pub_key: "ab12".into(),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "pub_key": "ab12" }));
    }

    #[test]
    fn greet_response_deserializes_from_server_public_key() {
        let resp: GreetResponse =
            serde_json::from_str(r#"{"server_public_key":"deadbeef"}"#).unwrap();
        assert_eq!(resp.server_public_key, "deadbeef");
    }

    #[test]
    fn register_request_has_token_and_ehlo() {
        let json = serde_json::to_value(RegisterRequest {
            token: "aa".into(),
            ehlo: "bb".into(),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "token": "aa", "ehlo": "bb" }));
    }

    #[test]
    fn resign_request_has_token_and_ehlo() {
        let json = serde_json::to_value(ReSignRequest {
            token: "cc".into(),
            ehlo: "dd".into(),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "token": "cc", "ehlo": "dd" }));
    }
}
