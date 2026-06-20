//! The two halves of the app's data flow (The Elm Architecture, see plan §5).
//!
//! - [`Message`] is something that *happened*: a key press, or the result of an
//!   async [`Command`]. Messages are fed to `App::update`, which mutates the model
//!   and may return more commands.
//! - [`Command`] is async work the model *asks for*: a network call or a blocking
//!   store read/write. The runtime executes it off the UI thread and reports back
//!   as a `Message`.
//!
//! `StoreState` is boxed inside `Message` so the enum stays small (the secret-
//! bearing variant would otherwise dominate `size_of::<Message>()`).

use ratatui::crossterm::event::KeyEvent;

use crate::store::StoreState;

/// An input event or the outcome of a [`Command`].
pub enum Message {
    /// A key was pressed (already filtered to `KeyEventKind::Press`).
    Key(KeyEvent),

    /// The local store was decrypted: we now hold the identity (verify pending).
    Unlocked(Box<StoreState>),
    /// Decrypting the store failed (wrong passphrase or corrupt file).
    UnlockFailed(String),

    /// Enrollment succeeded: keys generated, registered, and persisted.
    Enrolled(Box<StoreState>),
    /// Enrollment failed somewhere in greet → register → save.
    EnrollFailed(String),

    /// `/verify` returned 200 — the device is approved and the session is live.
    Verified,
    /// `/verify` returned 401 — not approved yet, or the source IP changed.
    VerifyUnauthorized,
    /// `/verify` failed for some other reason (network, 5xx, …).
    VerifyFailed(String),

    /// `/re-sign` succeeded — the identity is re-bound to this IP (needs re-approval).
    ReSigned,
    /// `/re-sign` failed.
    ReSignFailed(String),
}

/// Async work requested by `App::update`, executed on the tokio runtime.
///
/// Held passphrases are zeroized by the executor once consumed.
pub enum Command {
    /// Decrypt the local store with this passphrase.
    Unlock { passphrase: String },
    /// Generate keys, greet + register, and persist the store under this passphrase.
    Enroll { passphrase: String },
    /// Poll `/verify`, optionally after a delay (used to debounce approval polling).
    Verify { delay_ms: u64 },
    /// Re-bind the current identity to this IP via `/re-sign`.
    ReSign,
}
