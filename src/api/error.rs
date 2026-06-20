//! API error type and HTTP status mapping.
//!
//! The backend deliberately returns a generic `401 "unauthorized"` for several
//! distinct conditions (not yet approved by admin / wrong source IP / bad token),
//! so [`ApiError::Unauthorized`] carries a hint the UI can surface verbatim.

/// Errors returned by API calls.
#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    /// Transport-level failure (DNS, connect, timeout, TLS, body read).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// 400 — the request body failed validation server-side.
    #[error("bad request (400): {0}")]
    BadRequest(String),

    /// 401 — generic on this backend; could be any of several auth problems.
    #[error("unauthorized — device not approved yet, token is wrong, or your IP changed")]
    Unauthorized,

    /// 404 — resource not found.
    #[error("not found (404)")]
    NotFound,

    /// 409 — conflict (e.g. duplicate).
    #[error("conflict (409): {0}")]
    Conflict(String),

    /// 412 — this source IP already has an identity; `/greet` is one-shot per IP.
    #[error("this IP already has an identity (412) — greet is one-shot per IP")]
    IdentityExists,

    /// 429 — rate limited; the caller should back off (see protocol-notes limits).
    #[error("rate limited (429) — slow down and retry")]
    RateLimited,

    /// 5xx — server-side failure.
    #[error("server error ({status})")]
    Server { status: u16 },

    /// A 2xx body, or any status, that did not match what we expected.
    #[error("unexpected response (status {status}): {body}")]
    Unexpected { status: u16, body: String },

    /// The server's response was syntactically valid but semantically wrong
    /// (e.g. a public key that is not 32 bytes of hex).
    #[error("malformed server response: {0}")]
    Malformed(String),
}

/// Map a non-success HTTP status to an [`ApiError`]. `body` is the (already read)
/// response body, used for the variants that surface server detail.
///
/// Pure and total over the status codes this client cares about — unit-tested.
pub fn status_to_error(status: u16, body: String) -> ApiError {
    match status {
        400 => ApiError::BadRequest(body),
        401 => ApiError::Unauthorized,
        404 => ApiError::NotFound,
        409 => ApiError::Conflict(body),
        412 => ApiError::IdentityExists,
        429 => ApiError::RateLimited,
        500..=599 => ApiError::Server { status },
        _ => ApiError::Unexpected { status, body },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_statuses() {
        assert!(matches!(
            status_to_error(400, "bad name".into()),
            ApiError::BadRequest(b) if b == "bad name"
        ));
        assert!(matches!(
            status_to_error(401, String::new()),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            status_to_error(404, String::new()),
            ApiError::NotFound
        ));
        assert!(matches!(
            status_to_error(412, String::new()),
            ApiError::IdentityExists
        ));
        assert!(matches!(
            status_to_error(429, String::new()),
            ApiError::RateLimited
        ));
        assert!(matches!(
            status_to_error(503, String::new()),
            ApiError::Server { status: 503 }
        ));
    }

    #[test]
    fn maps_unknown_status_to_unexpected() {
        assert!(matches!(
            status_to_error(418, "teapot".into()),
            ApiError::Unexpected { status: 418, body } if body == "teapot"
        ));
    }

    #[test]
    fn unauthorized_message_is_a_helpful_hint() {
        // The UI shows this verbatim; keep it actionable (see protocol-notes §401).
        let msg = ApiError::Unauthorized.to_string();
        assert!(msg.contains("approved"));
        assert!(msg.contains("IP"));
    }
}
