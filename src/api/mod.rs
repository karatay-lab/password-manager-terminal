//! HTTP client for the password-manager backend.
//!
//! - [`ApiClient`] — configured reqwest wrapper (base URL, timeout, TLS).
//! - [`auth`] — enrollment + session endpoints (`/greet`, `/register`, `/verify`).
//! - [`vault`] — read-side group/password endpoints.
//! - [`ApiError`] — typed errors with a verified status-code mapping.
//!
//! Sealed payloads are produced/consumed by [`crate::crypto`]; the local secrets
//! they need live in [`crate::store`]. Wire shapes are pinned in
//! `docs/protocol-notes.md`.

pub mod auth;
pub mod client;
pub mod error;
pub mod models;
pub mod vault;

pub use client::{ApiClient, DEVICE_TOKEN_HEADER};
pub use error::ApiError;
