//! Native clipboard with timed auto-clear.
//!
//! The OS clipboard (X11 especially) is tied to a live owner connection, so we keep a
//! single [`arboard::Clipboard`] alive on a dedicated thread for the app's lifetime and
//! drive it over a channel — that keeps copied text available while the app runs, and
//! lets it vanish on quit (good for a password manager). `arboard::Clipboard` is `!Send`,
//! so it must be created and used on that one thread.
//!
//! If no clipboard backend can be initialized (a headless or SSH session with no
//! display), [`Clipboard`] degrades to a no-op and reports that it is unavailable,
//! rather than crashing the TUI.

use std::sync::mpsc::{self, Sender};
use std::thread;

enum ClipCommand {
    Set(String),
    Clear,
}

/// A cheap, clonable handle to the clipboard worker thread.
#[derive(Clone)]
pub struct Clipboard {
    /// `None` when no backend is available — every operation is then a no-op.
    tx: Option<Sender<ClipCommand>>,
}

impl Default for Clipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Clipboard {
    /// Open the system clipboard on a background thread. Returns a handle that is
    /// unavailable (a no-op) if no clipboard backend could be initialized.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<ClipCommand>();
        // The worker reports whether it could open a clipboard before we commit to it.
        let (ready_tx, ready_rx) = mpsc::channel::<bool>();

        thread::spawn(move || {
            let mut clipboard = match arboard::Clipboard::new() {
                Ok(c) => {
                    let _ = ready_tx.send(true);
                    c
                }
                Err(_) => {
                    let _ = ready_tx.send(false);
                    return;
                }
            };
            // Apply commands until the handle (and its `Sender`) is dropped.
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    ClipCommand::Set(text) => {
                        let _ = clipboard.set_text(text);
                    }
                    ClipCommand::Clear => {
                        let _ = clipboard.set_text(String::new());
                    }
                }
            }
        });

        let available = ready_rx.recv().unwrap_or(false);
        Self {
            tx: available.then_some(tx),
        }
    }

    /// Whether a clipboard backend is available in this environment.
    pub fn is_available(&self) -> bool {
        self.tx.is_some()
    }

    /// Put `text` on the clipboard. Returns `false` if no clipboard is available.
    pub fn set(&self, text: &str) -> bool {
        match &self.tx {
            Some(tx) => tx.send(ClipCommand::Set(text.to_string())).is_ok(),
            None => false,
        }
    }

    /// Clear the clipboard (best-effort; no-op if unavailable).
    pub fn clear(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(ClipCommand::Clear);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_clipboard_is_a_no_op() {
        // A handle with no backend never panics and reports unavailable.
        let cb = Clipboard { tx: None };
        assert!(!cb.is_available());
        assert!(!cb.set("secret"));
        cb.clear(); // must not panic
    }
}
