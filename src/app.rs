//! The application model, event loop, and async bridge (The Elm Architecture).
//!
//! The UI loop stays **synchronous**: it draws a frame, then waits a short tick for
//! a key press. All network + blocking crypto runs on a tokio [`Runtime`]; each
//! [`Command`] is spawned as a task that reports back through an `mpsc` channel as a
//! [`Message`]. `update` is the pure-ish core — it mutates the model and returns the
//! commands to run, which makes the state machine unit-testable without a backend.
//!
//! Flows (plan §8):
//! - **Enroll** (no local store): set a master passphrase → greet/register → poll
//!   `/verify` on the *awaiting-approval* screen until an admin approves.
//! - **Unlock** (store exists): passphrase → decrypt → `/verify`; on 401 offer
//!   `/re-sign` (re-binds the IP, but needs admin re-approval).

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use color_eyre::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use tokio::runtime::Runtime;
use zeroize::Zeroize;

use crate::api::models::{PwdDetail, PwdListItem};
use crate::api::{auth, vault, ApiClient, ApiError};
use crate::config::Config;
use crate::crypto;
use crate::message::{Command, Message};
use crate::secret::PwdSecret;
use crate::store::{Store, StoreError, StoreState};
use crate::ui;

/// How often to re-poll `/verify` while waiting for admin approval. The backend
/// allows `verify` at 10 rps; this is deliberately gentle (plan §9, debounce).
const POLL_INTERVAL_MS: u64 = 3000;
/// Max time we block for a key press before looping to drain async results.
const EVENT_TICK: Duration = Duration::from_millis(100);
/// Minimum master-passphrase length accepted at enrollment.
const MIN_PASSPHRASE_LEN: usize = 8;

/// Which screen is currently shown (and therefore how input is interpreted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// A store exists: prompt for the master passphrase to decrypt it.
    Unlock,
    /// No store yet: choose a master passphrase and enroll.
    Enroll,
    /// A blocking step is in flight after unlock (verifying with the server).
    Connecting,
    /// Registered/re-signed but unconfirmed: polling `/verify` for approval.
    AwaitingApproval,
    /// `/verify` returned 401 after unlock — offer re-sign or keep waiting.
    ReSignPrompt,
    /// The vault: a scrollable list of entries (valid or expired).
    Entries,
    /// One decrypted entry's fields.
    EntryDetail,
    /// The list of groups (read-only in v1's M4).
    Groups,
}

/// Which field the enroll form's cursor is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnrollField {
    Passphrase,
    Confirm,
}

/// A decrypted row shown in the entries list. Carries only the label fields
/// (username/url) — the password from the list blob is dropped after decoding.
pub struct EntryRow {
    pub uuid: String,
    pub username: String,
    pub url: String,
    /// Days until expiry (from the list endpoint); `0` on the expired list.
    pub expires: i64,
}

/// A group as shown in the groups list.
pub struct GroupRow {
    pub name: String,
    pub extra: Option<String>,
}

/// A fully decrypted entry for the detail screen. `secret` zeroizes on drop.
pub struct DetailView {
    pub name: Option<String>,
    pub group: Option<String>,
    pub expires: i64,
    pub valid_since_days: i64,
    pub created_at: String,
    pub secret: PwdSecret,
}

impl DetailView {
    fn from_response(resp: PwdDetail, secret: PwdSecret) -> Self {
        Self {
            name: resp.name,
            group: resp.group.map(|g| g.name),
            expires: resp.expires,
            valid_since_days: resp.valid_since_days,
            created_at: resp.created_at,
            secret,
        }
    }
}

/// Decrypt a list row into its display label, falling back to a placeholder if the
/// blob can't be opened (so one bad entry doesn't sink the whole list).
fn row_from_item(item: PwdListItem, key: &[u8; 32]) -> EntryRow {
    let (username, url) = match PwdSecret::open(&item.pwd, key) {
        Ok(secret) => {
            let username = if secret.username.is_empty() {
                "(no username)".to_string()
            } else {
                secret.username.clone()
            };
            (username, secret.url.clone())
        }
        Err(_) => ("(unreadable — wrong key?)".to_string(), String::new()),
    };
    EntryRow {
        uuid: item.uuid,
        username,
        url,
        expires: item.expires,
    }
}

/// Severity of the status-line message, used only for colour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusKind {
    Info,
    Success,
    Warning,
    Error,
}

/// A one-line message shown at the bottom of the screen.
#[derive(Clone)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
}

impl Status {
    fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Info,
        }
    }
    fn success(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Success,
        }
    }
    fn warning(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Warning,
        }
    }
    fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Error,
        }
    }
}

/// Top-level application state (the Model).
///
/// Fields read by the renderer are `pub`; the identity (secrets) stays private and
/// is only touched by [`App::dispatch`] when building a command's task.
pub struct App {
    pub config: Config,
    pub screen: Screen,
    /// Primary text field (passphrase on both entry screens).
    pub input: String,
    /// Confirm field (enroll only).
    pub confirm: String,
    pub enroll_field: EnrollField,
    pub status: Status,
    /// A command is in flight; entry screens ignore input while set.
    pub busy: bool,
    /// `/verify` has passed at least once this session.
    pub verified: bool,

    /// Entries currently listed, and which list (valid vs expired) they came from.
    pub entries: Vec<EntryRow>,
    pub show_expired: bool,
    /// Cursor position within [`App::entries`].
    pub selected: usize,
    /// Groups, populated when the groups screen is opened.
    pub groups: Vec<GroupRow>,
    /// The entry shown on the detail screen, if any.
    pub detail: Option<DetailView>,
    /// Whether the detail screen reveals the password in clear text.
    pub reveal: bool,

    /// The unlocked/enrolled identity. Secret — never rendered.
    identity: Option<StoreState>,
    api: ApiClient,
    store: Store,
    runtime: Runtime,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    running: bool,
}

impl App {
    /// Build the app: HTTP client, store handle, tokio runtime, and the message
    /// channel. The starting screen depends on whether a local store exists.
    pub fn new(config: Config) -> Result<Self> {
        let api = ApiClient::new(&config)?;
        let store = Store::new(&config);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (tx, rx) = mpsc::channel();

        let enrolled = store.exists();
        let (screen, status) = if enrolled {
            (
                Screen::Unlock,
                Status::info("Enter your master passphrase to unlock."),
            )
        } else {
            (
                Screen::Enroll,
                Status::info("No identity yet — set a master passphrase to enroll this device."),
            )
        };

        Ok(Self {
            config,
            screen,
            input: String::new(),
            confirm: String::new(),
            enroll_field: EnrollField::Passphrase,
            status,
            busy: false,
            verified: false,
            entries: Vec::new(),
            show_expired: false,
            selected: 0,
            groups: Vec::new(),
            detail: None,
            reveal: false,
            identity: None,
            api,
            store,
            runtime,
            tx,
            rx,
            running: false,
        })
    }

    /// Draw → wait for input (with a tick) → drain async results, until quit.
    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        self.running = true;
        while self.running {
            terminal.draw(|frame| ui::view(&self, frame))?;

            if event::poll(EVENT_TICK)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle(Message::Key(key));
                    }
                }
            }

            // Drain into a buffer first so the rx borrow ends before we mutate self.
            let mut pending = Vec::new();
            while let Ok(msg) = self.rx.try_recv() {
                pending.push(msg);
            }
            for msg in pending {
                self.handle(msg);
            }
        }
        Ok(())
    }

    /// Apply a message, then run any commands it produced.
    fn handle(&mut self, msg: Message) {
        for cmd in self.update(msg) {
            self.dispatch(cmd);
        }
    }

    /// Pure-ish state transition: mutate the model, return commands to run.
    fn update(&mut self, msg: Message) -> Vec<Command> {
        match msg {
            Message::Key(key) => self.on_key(key),

            Message::Unlocked(state) => {
                self.identity = Some(*state);
                self.busy = false;
                self.screen = Screen::Connecting;
                self.status = Status::info("Verifying with the server…");
                vec![Command::Verify { delay_ms: 0 }]
            }
            Message::UnlockFailed(err) => {
                self.busy = false;
                self.status = Status::error(err);
                vec![]
            }

            Message::Enrolled(state) => {
                self.identity = Some(*state);
                self.busy = false;
                self.screen = Screen::AwaitingApproval;
                self.status =
                    Status::info("Registered. Waiting for an admin to approve this device…");
                vec![Command::Verify { delay_ms: 0 }]
            }
            Message::EnrollFailed(err) => {
                self.busy = false;
                self.screen = Screen::Enroll;
                self.status = Status::error(err);
                vec![]
            }

            Message::Verified => {
                self.verified = true;
                self.busy = false;
                self.screen = Screen::Entries;
                self.status = Status::info("Session established — loading entries…");
                vec![Command::LoadPasswords { expired: false }]
            }
            Message::VerifyUnauthorized => match self.screen {
                Screen::AwaitingApproval => {
                    self.status = Status::info("Still waiting for admin approval…");
                    vec![Command::Verify {
                        delay_ms: POLL_INTERVAL_MS,
                    }]
                }
                Screen::Connecting => {
                    self.screen = Screen::ReSignPrompt;
                    self.status =
                        Status::warning("Not authorized — not approved yet, or your IP changed.");
                    vec![]
                }
                _ => vec![],
            },
            Message::VerifyFailed(err) => {
                self.status = Status::error(format!("Verify failed: {err}"));
                if self.screen == Screen::AwaitingApproval {
                    vec![Command::Verify {
                        delay_ms: POLL_INTERVAL_MS,
                    }]
                } else {
                    vec![]
                }
            }

            Message::ReSigned => {
                self.busy = false;
                self.screen = Screen::AwaitingApproval;
                self.status = Status::info("Re-signed. An admin must re-approve this device…");
                vec![Command::Verify { delay_ms: 0 }]
            }
            Message::ReSignFailed(err) => {
                self.busy = false;
                self.status = Status::error(format!("Re-sign failed: {err}"));
                vec![]
            }

            Message::PasswordsLoaded { expired, rows } => {
                self.show_expired = expired;
                self.entries = rows;
                self.selected = 0;
                self.screen = Screen::Entries;
                let n = self.entries.len();
                let kind = if expired { "expired" } else { "valid" };
                self.status = Status::success(format!(
                    "{n} {kind} {}",
                    if n == 1 { "entry" } else { "entries" }
                ));
                vec![]
            }
            Message::GroupsLoaded(rows) => {
                self.groups = rows;
                self.screen = Screen::Groups;
                let n = self.groups.len();
                self.status =
                    Status::info(format!("{n} {}", if n == 1 { "group" } else { "groups" }));
                vec![]
            }
            Message::EntryLoaded(detail) => {
                self.detail = Some(*detail);
                self.reveal = false;
                self.screen = Screen::EntryDetail;
                self.status = Status::info("Entry decrypted. Press s to reveal the password.");
                vec![]
            }
            Message::VaultFailed(err) => {
                self.busy = false;
                self.status = Status::error(err);
                vec![]
            }
        }
    }

    /// Route a key press to the active screen's handler.
    fn on_key(&mut self, key: KeyEvent) -> Vec<Command> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return vec![];
        }
        match self.screen {
            Screen::Unlock => self.on_key_unlock(key),
            Screen::Enroll => self.on_key_enroll(key),
            Screen::ReSignPrompt => self.on_key_resign(key),
            Screen::Entries => self.on_key_entries(key),
            Screen::Groups => self.on_key_groups(key),
            Screen::EntryDetail => self.on_key_detail(key),
            Screen::Connecting | Screen::AwaitingApproval => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                    self.running = false;
                }
                vec![]
            }
        }
    }

    fn on_key_unlock(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.busy {
            return vec![];
        }
        match key.code {
            KeyCode::Esc => {
                self.running = false;
                vec![]
            }
            KeyCode::Enter => {
                if self.input.is_empty() {
                    self.status = Status::warning("Enter your passphrase.");
                    return vec![];
                }
                let passphrase = std::mem::take(&mut self.input);
                self.busy = true;
                self.status = Status::info("Unlocking…");
                vec![Command::Unlock { passphrase }]
            }
            KeyCode::Backspace => {
                self.input.pop();
                vec![]
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                vec![]
            }
            _ => vec![],
        }
    }

    fn on_key_enroll(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.busy {
            return vec![];
        }
        match key.code {
            KeyCode::Esc => {
                self.running = false;
                vec![]
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                self.enroll_field = match self.enroll_field {
                    EnrollField::Passphrase => EnrollField::Confirm,
                    EnrollField::Confirm => EnrollField::Passphrase,
                };
                vec![]
            }
            KeyCode::Enter => self.submit_enroll(),
            KeyCode::Backspace => {
                self.focused_field_mut().pop();
                vec![]
            }
            KeyCode::Char(c) => {
                self.focused_field_mut().push(c);
                vec![]
            }
            _ => vec![],
        }
    }

    /// Validate the enroll form and, if it's sound, emit the enroll command.
    fn submit_enroll(&mut self) -> Vec<Command> {
        if self.input.is_empty() || self.confirm.is_empty() {
            self.status = Status::warning("Fill in both passphrase fields.");
            return vec![];
        }
        if self.input != self.confirm {
            self.status = Status::error("Passphrases don't match.");
            self.confirm.zeroize();
            self.enroll_field = EnrollField::Confirm;
            return vec![];
        }
        if self.input.chars().count() < MIN_PASSPHRASE_LEN {
            self.status = Status::warning(format!("Use at least {MIN_PASSPHRASE_LEN} characters."));
            return vec![];
        }
        let passphrase = std::mem::take(&mut self.input);
        self.confirm.zeroize();
        self.busy = true;
        self.status = Status::info("Generating keys and registering…");
        vec![Command::Enroll { passphrase }]
    }

    fn on_key_resign(&mut self, key: KeyEvent) -> Vec<Command> {
        match key.code {
            KeyCode::Char('r') => {
                self.busy = true;
                self.status = Status::info("Re-signing…");
                vec![Command::ReSign]
            }
            KeyCode::Char('w') => {
                self.screen = Screen::AwaitingApproval;
                self.status = Status::info("Waiting for admin approval…");
                vec![Command::Verify { delay_ms: 0 }]
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.running = false;
                vec![]
            }
            _ => vec![],
        }
    }

    fn focused_field_mut(&mut self) -> &mut String {
        match self.enroll_field {
            EnrollField::Passphrase => &mut self.input,
            EnrollField::Confirm => &mut self.confirm,
        }
    }

    fn on_key_entries(&mut self, key: KeyEvent) -> Vec<Command> {
        match key.code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                vec![]
            }
            KeyCode::Down => {
                if self.selected + 1 < self.entries.len() {
                    self.selected += 1;
                }
                vec![]
            }
            KeyCode::Enter => match self.entries.get(self.selected) {
                Some(row) => {
                    let uuid = row.uuid.clone();
                    self.status = Status::info("Loading entry…");
                    vec![Command::LoadEntry { uuid }]
                }
                None => vec![],
            },
            KeyCode::Char('t') => {
                let expired = !self.show_expired;
                self.status = Status::info("Loading…");
                vec![Command::LoadPasswords { expired }]
            }
            KeyCode::Char('g') => {
                self.status = Status::info("Loading groups…");
                vec![Command::LoadGroups]
            }
            KeyCode::Char('r') => {
                let expired = self.show_expired;
                self.status = Status::info("Refreshing…");
                vec![Command::LoadPasswords { expired }]
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.running = false;
                vec![]
            }
            _ => vec![],
        }
    }

    fn on_key_groups(&mut self, key: KeyEvent) -> Vec<Command> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Entries;
                vec![]
            }
            KeyCode::Char('q') => {
                self.running = false;
                vec![]
            }
            _ => vec![],
        }
    }

    fn on_key_detail(&mut self, key: KeyEvent) -> Vec<Command> {
        match key.code {
            KeyCode::Char('s') => {
                self.reveal = !self.reveal;
                vec![]
            }
            KeyCode::Esc => {
                self.detail = None;
                self.reveal = false;
                self.screen = Screen::Entries;
                vec![]
            }
            KeyCode::Char('q') => {
                self.running = false;
                vec![]
            }
            _ => vec![],
        }
    }

    /// Spawn the async/blocking task for a command; it reports back via `tx`.
    fn dispatch(&mut self, cmd: Command) {
        let tx = self.tx.clone();
        let client = self.api.clone();
        match cmd {
            Command::Unlock { passphrase } => {
                let store = self.store.clone();
                self.runtime.spawn_blocking(move || {
                    let mut passphrase = passphrase;
                    let result = store.load(&passphrase);
                    passphrase.zeroize();
                    let msg = match result {
                        Ok(state) => Message::Unlocked(Box::new(state)),
                        Err(StoreError::WrongPassphrase) => Message::UnlockFailed(
                            "Wrong passphrase, or the store file is corrupt.".into(),
                        ),
                        Err(e) => Message::UnlockFailed(e.to_string()),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::Enroll { passphrase } => {
                let store = self.store.clone();
                self.runtime.spawn(async move {
                    let mut passphrase = passphrase;
                    let outcome = enroll(&client, &store, &passphrase).await;
                    passphrase.zeroize();
                    let msg = match outcome {
                        Ok(state) => Message::Enrolled(Box::new(state)),
                        Err(e) => Message::EnrollFailed(e),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::Verify { delay_ms } => {
                let token = match &self.identity {
                    Some(state) => state.device_token.clone(),
                    None => return,
                };
                self.runtime.spawn(async move {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let msg = match auth::verify(&client, &token).await {
                        Ok(()) => Message::Verified,
                        Err(ApiError::Unauthorized) => Message::VerifyUnauthorized,
                        Err(e) => Message::VerifyFailed(e.to_string()),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::ReSign => {
                let (token, ehlo, private, server) = match &self.identity {
                    Some(state) => (
                        state.device_token.clone(),
                        state.ehlo_secret.clone(),
                        state.client_private,
                        state.server_public,
                    ),
                    None => return,
                };
                self.runtime.spawn(async move {
                    let shared = crypto::derive_shared_key(&private, &server);
                    let token_hex = hex::encode(token.as_bytes());
                    let ehlo_sealed = crypto::seal_hex(ehlo.as_bytes(), &shared);
                    let msg = match auth::re_sign(&client, &token_hex, &ehlo_sealed).await {
                        Ok(()) => Message::ReSigned,
                        Err(e) => Message::ReSignFailed(e.to_string()),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::LoadPasswords { expired } => {
                let Some((token, key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    let msg = match vault::list_passwords(&client, &token, expired).await {
                        Ok(items) => {
                            let rows = items
                                .into_iter()
                                .map(|item| row_from_item(item, &key))
                                .collect();
                            Message::PasswordsLoaded { expired, rows }
                        }
                        Err(e) => Message::VaultFailed(vault_error("load entries", &e)),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::LoadGroups => {
                let Some((token, _key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    let msg = match vault::list_groups(&client, &token).await {
                        Ok(groups) => Message::GroupsLoaded(
                            groups
                                .into_iter()
                                .map(|g| GroupRow {
                                    name: g.name,
                                    extra: g.extra,
                                })
                                .collect(),
                        ),
                        Err(e) => Message::VaultFailed(vault_error("load groups", &e)),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::LoadEntry { uuid } => {
                let Some((token, key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    let msg = match vault::get_password(&client, &token, &uuid).await {
                        Ok(resp) => match PwdSecret::open(&resp.pwd, &key) {
                            Ok(secret) => Message::EntryLoaded(Box::new(
                                DetailView::from_response(resp, secret),
                            )),
                            Err(e) => Message::VaultFailed(format!("Couldn't decrypt entry: {e}")),
                        },
                        Err(e) => Message::VaultFailed(vault_error("load entry", &e)),
                    };
                    let _ = tx.send(msg);
                });
            }
        }
    }

    /// The device token and shared key for the current session, if unlocked.
    fn session_credentials(&self) -> Option<(String, [u8; 32])> {
        self.identity
            .as_ref()
            .map(|state| (state.device_token.clone(), state.shared_key()))
    }
}

/// Build a display-ready error string for a failed vault read, turning the generic
/// 401 into the actionable hint the backend can't give us (plan §9).
fn vault_error(action: &str, err: &ApiError) -> String {
    match err {
        ApiError::Unauthorized => {
            "Authorization lost — your IP may have changed. Restart to unlock and re-sign.".into()
        }
        other => format!("Couldn't {action}: {other}"),
    }
}

/// Full enrollment: keygen → `/greet` → derive key → seal + `/register` → persist.
///
/// Returns the established (but unconfirmed) identity, or a display-ready error.
async fn enroll(client: &ApiClient, store: &Store, passphrase: &str) -> Result<StoreState, String> {
    let keypair = crypto::generate_keypair();
    let server_public = auth::greet(client, &keypair.public)
        .await
        .map_err(|e| e.to_string())?;

    let shared = crypto::derive_shared_key(&keypair.private, &server_public);
    let device_token = crypto::random_token();
    let ehlo_secret = crypto::random_token();
    let sealed_token = crypto::seal_hex(device_token.as_bytes(), &shared);
    let sealed_ehlo = crypto::seal_hex(ehlo_secret.as_bytes(), &shared);

    auth::register(client, &sealed_token, &sealed_ehlo)
        .await
        .map_err(|e| e.to_string())?;

    let state = StoreState {
        client_private: keypair.private,
        client_public: keypair.public,
        server_public,
        device_token,
        ehlo_secret,
    };

    // Argon2id + write is CPU/IO-bound — keep it off the async worker.
    let store = store.clone();
    let to_save = state.clone();
    let passphrase = passphrase.to_string();
    tokio::task::spawn_blocking(move || store.save(&to_save, &passphrase))
        .await
        .map_err(|e| format!("save task failed: {e}"))?
        .map_err(|e| e.to_string())?;

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;
    use std::path::Path;

    fn config_in(dir: &Path) -> Config {
        Config {
            api_base_url: "http://localhost:53971".into(),
            request_timeout_secs: 30,
            verify_tls: true,
            data_dir: dir.to_string_lossy().into_owned(),
            clipboard_clear_secs: 30,
        }
    }

    fn app_in(dir: &Path) -> App {
        App::new(config_in(dir)).unwrap()
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle(Message::Key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    #[test]
    fn starts_on_enroll_without_a_store() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(app_in(dir.path()).screen, Screen::Enroll);
    }

    #[test]
    fn starts_on_unlock_when_a_store_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        std::fs::write(store.path(), b"PWMS-pretend-store").unwrap();
        assert_eq!(app_in(dir.path()).screen, Screen::Unlock);
    }

    #[test]
    fn unlock_enter_emits_unlock_command_with_typed_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        std::fs::write(store.path(), b"x").unwrap();
        let mut app = app_in(dir.path());

        type_str(&mut app, "hunter2");
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert!(
            matches!(cmds.as_slice(), [Command::Unlock { passphrase }] if passphrase == "hunter2")
        );
        assert!(app.input.is_empty(), "input is cleared on submit");
        assert!(app.busy);
    }

    #[test]
    fn enroll_rejects_mismatched_passphrases() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());

        type_str(&mut app, "longenough1");
        press(&mut app, KeyCode::Tab);
        type_str(&mut app, "different22");
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Error);
        assert!(app.confirm.is_empty(), "confirm is wiped on mismatch");
    }

    #[test]
    fn enroll_rejects_short_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());

        type_str(&mut app, "short"); // < MIN_PASSPHRASE_LEN
        press(&mut app, KeyCode::Tab);
        type_str(&mut app, "short");
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn enroll_matching_passphrase_emits_enroll_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());

        type_str(&mut app, "correct horse");
        press(&mut app, KeyCode::Tab);
        type_str(&mut app, "correct horse");
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert!(
            matches!(cmds.as_slice(), [Command::Enroll { passphrase }] if passphrase == "correct horse")
        );
        assert!(app.busy);
    }

    #[test]
    fn verified_message_loads_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        let cmds = app.update(Message::Verified);
        assert_eq!(app.screen, Screen::Entries);
        assert!(app.verified);
        assert!(matches!(
            cmds.as_slice(),
            [Command::LoadPasswords { expired: false }]
        ));
    }

    fn rows(specs: &[(&str, &str)]) -> Vec<EntryRow> {
        specs
            .iter()
            .map(|(uuid, user)| EntryRow {
                uuid: (*uuid).into(),
                username: (*user).into(),
                url: String::new(),
                expires: 7,
            })
            .collect()
    }

    #[test]
    fn passwords_loaded_populates_and_resets_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.selected = 5;
        let cmds = app.update(Message::PasswordsLoaded {
            expired: true,
            rows: rows(&[("a", "alice"), ("b", "bob")]),
        });
        assert!(cmds.is_empty());
        assert_eq!(app.screen, Screen::Entries);
        assert!(app.show_expired);
        assert_eq!(app.entries.len(), 2);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn entries_down_then_enter_loads_selected_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.entries = rows(&[("a", "alice"), ("b", "bob")]);

        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected, 1);
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(matches!(cmds.as_slice(), [Command::LoadEntry { uuid }] if uuid == "b"));
    }

    #[test]
    fn entries_down_is_clamped_at_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.entries = rows(&[("a", "alice")]);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn entries_t_toggles_to_expired_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.show_expired = false;
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Char('t'),
            KeyModifiers::NONE,
        )));
        assert!(matches!(
            cmds.as_slice(),
            [Command::LoadPasswords { expired: true }]
        ));
    }

    #[test]
    fn entries_g_requests_groups() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Char('g'),
            KeyModifiers::NONE,
        )));
        assert!(matches!(cmds.as_slice(), [Command::LoadGroups]));
    }

    #[test]
    fn entry_detail_toggles_reveal_with_s() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::EntryDetail;
        app.detail = Some(DetailView {
            name: None,
            group: None,
            expires: 1,
            valid_since_days: 30,
            created_at: String::new(),
            secret: PwdSecret::default(),
        });
        assert!(!app.reveal);
        press(&mut app, KeyCode::Char('s'));
        assert!(app.reveal);
        press(&mut app, KeyCode::Char('s'));
        assert!(!app.reveal);
    }

    #[test]
    fn entry_detail_esc_returns_to_entries_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::EntryDetail;
        app.detail = Some(DetailView {
            name: None,
            group: None,
            expires: 1,
            valid_since_days: 30,
            created_at: String::new(),
            secret: PwdSecret::default(),
        });
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Entries);
        assert!(app.detail.is_none());
    }

    #[test]
    fn unauthorized_while_awaiting_re_polls() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::AwaitingApproval;
        let cmds = app.update(Message::VerifyUnauthorized);
        assert!(matches!(cmds.as_slice(), [Command::Verify { delay_ms }] if *delay_ms > 0));
        assert_eq!(app.screen, Screen::AwaitingApproval);
    }

    #[test]
    fn unauthorized_after_unlock_offers_resign() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Connecting;
        let cmds = app.update(Message::VerifyUnauthorized);
        assert!(cmds.is_empty());
        assert_eq!(app.screen, Screen::ReSignPrompt);
    }

    #[test]
    fn resign_prompt_r_emits_resign_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::ReSignPrompt;
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Char('r'),
            KeyModifiers::NONE,
        )));
        assert!(matches!(cmds.as_slice(), [Command::ReSign]));
        assert!(app.busy);
    }

    #[test]
    fn resign_success_returns_to_awaiting_and_polls() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::ReSignPrompt;
        let cmds = app.update(Message::ReSigned);
        assert_eq!(app.screen, Screen::AwaitingApproval);
        assert!(matches!(cmds.as_slice(), [Command::Verify { .. }]));
    }
}
