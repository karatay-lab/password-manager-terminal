//! Request/response DTOs for the enrollment + vault endpoints.
//!
//! Shapes are taken from `docs/protocol-notes.md` (verified against backend source).
//! All sealed fields (`token`, `ehlo`, `pwd`) are hex strings of `nonce‖ct‖tag`
//! produced by [`crate::crypto`]; the server only ever sees ciphertext. The `name`
//! and `extra` fields are **plaintext** server-side — never put secrets there.

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

/// `POST /group/create` request. `name` ≤128 chars (server-enforced); `extra` is
/// optional plaintext metadata.
#[derive(Debug, Serialize)]
pub struct GroupCreateRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
}

/// `POST /pwd/create` request. `pwd` is sealed hex; `name`/`extra` are **plaintext**
/// server-side (never secrets). `valid_since_days` (1–365, default 30 server-side)
/// sets the expiry window. There is no update endpoint, so a "renew" is just a fresh
/// create (see `docs/protocol-notes.md`); `None` fields are omitted so the server
/// applies its defaults.
#[derive(Debug, Serialize)]
pub struct PwdCreateRequest {
    pub pwd: String,
    pub group_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_since_days: Option<i64>,
}

/// `GET /group/list` item, and the `POST /group/create` response (plaintext).
#[derive(Debug, Deserialize)]
pub struct GroupSummary {
    pub uuid: String,
    pub name: String,
    #[serde(default)]
    pub extra: Option<String>,
}

/// One row from `GET /pwd/list/{valid,expired}`. `pwd` is sealed hex; `expires` is
/// days remaining (always `0` on the expired list). No `name` here — only `get`
/// returns it.
#[derive(Debug, Deserialize)]
pub struct PwdListItem {
    pub uuid: String,
    pub pwd: String,
    #[serde(default)]
    pub expires: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub valid_since_days: i64,
}

/// Plaintext group reference embedded in a [`PwdDetail`].
#[derive(Debug, Deserialize)]
pub struct GroupRef {
    pub name: String,
    #[serde(default)]
    pub extra: Option<String>,
}

/// `GET /pwd/get/{uuid}` — a full entry. `pwd` is sealed hex; `name`/`extra`/`group`
/// are plaintext.
#[derive(Debug, Deserialize)]
pub struct PwdDetail {
    pub uuid: String,
    pub pwd: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub extra: Option<String>,
    #[serde(default)]
    pub expires: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub valid_since_days: i64,
    #[serde(default)]
    pub group: Option<GroupRef>,
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

    #[test]
    fn group_create_request_omits_none_extra() {
        let json = serde_json::to_value(GroupCreateRequest {
            name: "Work".into(),
            extra: None,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "name": "Work" }));
    }

    #[test]
    fn pwd_create_request_omits_none_fields() {
        let json = serde_json::to_value(PwdCreateRequest {
            pwd: "deadbeef".into(),
            group_id: "g1".into(),
            name: None,
            extra: None,
            valid_since_days: Some(30),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "pwd": "deadbeef", "group_id": "g1", "valid_since_days": 30 })
        );
    }

    #[test]
    fn group_summary_deserializes() {
        let g: GroupSummary =
            serde_json::from_str(r#"{"uuid":"g1","name":"Work","extra":null}"#).unwrap();
        assert_eq!(g.uuid, "g1");
        assert_eq!(g.name, "Work");
        assert!(g.extra.is_none());
    }

    #[test]
    fn pwd_list_item_deserializes_with_sealed_pwd() {
        let item: PwdListItem = serde_json::from_str(
            r#"{"uuid":"p1","pwd":"deadbeef","expires":12,"created_at":"2026-06-20","valid_since_days":30}"#,
        )
        .unwrap();
        assert_eq!(item.uuid, "p1");
        assert_eq!(item.pwd, "deadbeef");
        assert_eq!(item.expires, 12);
    }

    #[test]
    fn pwd_detail_deserializes_with_group_and_optional_name() {
        let d: PwdDetail = serde_json::from_str(
            r#"{"uuid":"p1","pwd":"ab","expires":0,"valid_since_days":30,"group":{"name":"Work"}}"#,
        )
        .unwrap();
        assert_eq!(d.uuid, "p1");
        assert!(d.name.is_none());
        assert_eq!(d.group.unwrap().name, "Work");
    }
}
