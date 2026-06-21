//! Read-side vault endpoints: list groups, list passwords, fetch one entry.
//!
//! All require the `device-token` header (the identity must be approved). The `pwd`
//! field on the returned rows is sealed hex — decrypt it client-side with
//! [`crate::secret::PwdSecret::open`]. See `docs/protocol-notes.md` §Endpoints.

use super::client::{check_status, ApiClient, DEVICE_TOKEN_HEADER};
use super::error::ApiError;
use super::models::{GroupSummary, PwdDetail, PwdListItem};

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

/// `GET /pwd/list/valid` or `/pwd/list/expired` — entry rows with sealed `pwd`.
///
/// Uses the server's default page size; pagination is deferred (plan §2).
pub async fn list_passwords(
    client: &ApiClient,
    device_token: &str,
    expired: bool,
) -> Result<Vec<PwdListItem>, ApiError> {
    let path = if expired {
        "/pwd/list/expired"
    } else {
        "/pwd/list/valid"
    };
    let resp = client
        .http()
        .get(client.url(path))
        .header(DEVICE_TOKEN_HEADER, device_token)
        .send()
        .await?;
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
