//! pwd-manager-terminal — a ratatui TUI client for the password-manager backend.
//!
//! Library crate holding the app modules; the binary in `main.rs` is a thin shell
//! around [`app::App`]. Splitting lib/bin keeps modules built ahead of their first
//! use (e.g. `crypto` in M1) part of the public API rather than dead code.

pub mod api;
pub mod app;
pub mod config;
pub mod crypto;
pub mod message;
pub mod store;
pub mod ui;
