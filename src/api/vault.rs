//! Vault endpoints: list/create groups, list/create passwords, fetch one entry.
//!
//! All require the `device-token` header (the identity must be approved). The `pwd`
//! field is sealed hex — decrypt it client-side with [`crate::secret::PwdSecret::open`]
//! and seal new entries with [`crate::secret::PwdSecret::seal`]. See
//! `docs/protocol-notes.md` §Endpoints.

use super::client::{check_status, ApiClient, DEVICE_TOKEN_HEADER};
use super::error::ApiError;
use super::models::{
    GroupCreateRequest, GroupSummary, PwdCreateRequest, PwdDetail, PwdListItem, PwdUpdateRequest,
};

/// `GET /group/list` — all groups (plaintext metadata).
pub async fn list_groups(
    client: &ApiClient,
    device_token: &str,
) -> Result<Vec<GroupSummary>, ApiError> {
    let resp = client
        .http()
        .get(client.url("/group/list"))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    Ok(resp.json().await?)
}

/// `GET /pwd/list` — entry rows with sealed `pwd`. `?expired=true` returns only
/// expired entries; omitting it returns the valid (non-expired) ones.
///
/// Uses the server's default page size; pagination is deferred (plan §2).
pub async fn list_passwords(
    client: &ApiClient,
    device_token: &str,
    expired: bool,
) -> Result<Vec<PwdListItem>, ApiError> {
    let mut req = client
        .http()
        .get(client.url("/pwd/list"))
        .header(DEVICE_TOKEN_HEADER, device_token);
    if expired {
        req = req.query(&[("expired", "true")]);
    }
    let resp = req.send().await?;
    let resp = check_status(resp).await?;
    Ok(resp.json().await?)
}

/// `GET /pwd/get/{uuid}` — a single entry, including its sealed `pwd`.
pub async fn get_password(
    client: &ApiClient,
    device_token: &str,
    uuid: &str,
) -> Result<PwdDetail, ApiError> {
    let resp = client
        .http()
        .get(client.url(&format!("/pwd/get/{uuid}")))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    Ok(resp.json().await?)
}

/// `POST /group/create` — create a group, returning its server-assigned uuid.
pub async fn create_group(
    client: &ApiClient,
    device_token: &str,
    name: &str,
    extra: Option<&str>,
) -> Result<GroupSummary, ApiError> {
    let body = GroupCreateRequest {
        name: name.to_string(),
        extra: extra.map(str::to_string),
    };
    let resp = client
        .http()
        .post(client.url("/group/create"))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .json(&body)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    Ok(resp.json().await?)
}

/// `POST /pwd/create` — store a new (sealed) entry, returning the created row.
///
/// Use this for brand-new entries, or to "renew" an expiring one with a fresh
/// expiry clock (a renew is a new create; the old row persists). To change an
/// existing entry's content in place, use [`update_password`] instead.
pub async fn create_password(
    client: &ApiClient,
    device_token: &str,
    req: &PwdCreateRequest,
) -> Result<PwdDetail, ApiError> {
    let resp = client
        .http()
        .post(client.url("/pwd/create"))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .json(req)
        .send()
        .await?;
    let resp = check_status(resp).await?;
    Ok(resp.json().await?)
}

/// `PUT /pwd/update/{uuid}` — overwrite an existing entry's content in place
/// (no duplicate row). Updates `pwd`/`group`/`name`/`extra` but NOT the expiry
/// window or `created_at` — the backend leaves `valid_since_days` untouched
/// (see `docs/protocol-notes.md` row 11). Returns `null` on success.
pub async fn update_password(
    client: &ApiClient,
    device_token: &str,
    uuid: &str,
    req: &PwdUpdateRequest,
) -> Result<(), ApiError> {
    let resp = client
        .http()
        .put(client.url(&format!("/pwd/update/{uuid}")))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .json(req)
        .send()
        .await?;
    check_status(resp).await?;
    Ok(())
}
