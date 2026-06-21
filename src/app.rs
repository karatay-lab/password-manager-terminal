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
use std::time::{Duration, Instant};

use color_eyre::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use tokio::runtime::Runtime;
use zeroize::Zeroize;

use crate::api::models::{PwdCreateRequest, PwdDetail, PwdListItem};
use crate::api::{auth, vault, ApiClient, ApiError};
use crate::clipboard::Clipboard;
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
/// Length of a password produced by the in-form generator.
const GENERATED_PASSWORD_LEN: usize = 20;
/// Default expiry window for a new entry when the field is left blank.
const DEFAULT_VALID_DAYS: i64 = 30;
/// Server-enforced bounds for `valid_since_days`.
const MIN_VALID_DAYS: i64 = 1;
const MAX_VALID_DAYS: i64 = 365;
/// Server-enforced max group-name length.
const MAX_GROUP_NAME_LEN: usize = 128;
/// Server-enforced max entry-name length.
const MAX_ENTRY_NAME_LEN: usize = 256;

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
    /// Confirm rotating the device token via `/refresh` (asks for the passphrase).
    RefreshPrompt,
    /// The vault: a scrollable list of entries (valid or expired).
    Entries,
    /// One decrypted entry's fields.
    EntryDetail,
    /// The list of groups.
    Groups,
    /// Form to create a new entry (also used to renew an existing one).
    NewEntry,
    /// Form to create a new group.
    NewGroup,
}

/// Which field the enroll form's cursor is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnrollField {
    Passphrase,
    Confirm,
}

/// Which field the new-entry form's cursor is on (in tab order).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryField {
    Name,
    Group,
    Username,
    Password,
    Url,
    Notes,
    ValidDays,
}

impl EntryField {
    /// Fields in tab order.
    const ORDER: [EntryField; 7] = [
        EntryField::Name,
        EntryField::Group,
        EntryField::Username,
        EntryField::Password,
        EntryField::Url,
        EntryField::Notes,
        EntryField::ValidDays,
    ];

    fn next(self) -> Self {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    fn prev(self) -> Self {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
}

/// Which field the new-group form's cursor is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupField {
    Name,
    Extra,
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

/// A group as shown in the groups list. `uuid` is needed to file new entries.
pub struct GroupRow {
    pub uuid: String,
    pub name: String,
    pub extra: Option<String>,
}

/// The new-entry / renew form. Text fields are edited in place; `group_idx`
/// indexes into [`App::groups`]. Secret fields are zeroized on drop.
pub struct EntryForm {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub valid_days: String,
    pub group_idx: usize,
    pub field: EntryField,
    /// True when pre-filled from an existing entry (a renew → fresh create).
    pub renewing: bool,
}

impl EntryForm {
    fn blank(group_idx: usize) -> Self {
        Self {
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            valid_days: DEFAULT_VALID_DAYS.to_string(),
            group_idx,
            field: EntryField::Name,
            renewing: false,
        }
    }

    /// The text field under the cursor, or `None` when the group picker is focused.
    fn focused_mut(&mut self) -> Option<&mut String> {
        match self.field {
            EntryField::Name => Some(&mut self.name),
            EntryField::Username => Some(&mut self.username),
            EntryField::Password => Some(&mut self.password),
            EntryField::Url => Some(&mut self.url),
            EntryField::Notes => Some(&mut self.notes),
            EntryField::ValidDays => Some(&mut self.valid_days),
            EntryField::Group => None,
        }
    }
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        self.password.zeroize();
        self.username.zeroize();
        self.notes.zeroize();
    }
}

/// The new-group form. Both fields are server-plaintext (no secrets).
pub struct GroupForm {
    pub name: String,
    pub extra: String,
    pub field: GroupField,
}

impl GroupForm {
    fn blank() -> Self {
        Self {
            name: String::new(),
            extra: String::new(),
            field: GroupField::Name,
        }
    }

    fn focused_mut(&mut self) -> &mut String {
        match self.field {
            GroupField::Name => &mut self.name,
            GroupField::Extra => &mut self.extra,
        }
    }
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
    /// The new-entry/renew form, when that screen is active.
    pub entry_form: Option<EntryForm>,
    /// The new-group form, when that screen is active.
    pub group_form: Option<GroupForm>,
    /// Active entries-list filter (`""` = no filter).
    pub search: String,
    /// Whether the entries list is currently capturing search keystrokes.
    pub searching: bool,
    /// Whether the help overlay is shown.
    pub show_help: bool,

    /// The unlocked/enrolled identity. Secret — never rendered.
    identity: Option<StoreState>,
    api: ApiClient,
    store: Store,
    clipboard: Clipboard,
    runtime: Runtime,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    /// Idle auto-lock window (`None` disables it). Measured from [`App::last_activity`].
    idle_timeout: Option<Duration>,
    /// When the user last pressed a key — drives idle auto-lock.
    last_activity: Instant,
    running: bool,
}

impl Drop for App {
    /// Wipe the passphrase fields on quit. Other secrets zeroize via their own `Drop`
    /// (`identity`/`StoreState`, `entry_form`/`EntryForm`, `detail`/`PwdSecret`).
    fn drop(&mut self) {
        self.input.zeroize();
        self.confirm.zeroize();
    }
}

impl App {
    /// Build the app: HTTP client, store handle, tokio runtime, and the message
    /// channel. The starting screen depends on whether a local store exists.
    pub fn new(config: Config) -> Result<Self> {
        let api = ApiClient::new(&config)?;
        let store = Store::new(&config);
        let clipboard = Clipboard::new();
        let idle_timeout =
            (config.idle_lock_secs > 0).then(|| Duration::from_secs(config.idle_lock_secs));
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
            entry_form: None,
            group_form: None,
            search: String::new(),
            searching: false,
            show_help: false,
            identity: None,
            api,
            store,
            clipboard,
            runtime,
            tx,
            rx,
            idle_timeout,
            last_activity: Instant::now(),
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
                        self.last_activity = Instant::now();
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

            if self.idle_expired(Instant::now()) {
                self.lock();
            }
        }
        Ok(())
    }

    /// Whether the idle window has elapsed while the vault is unlocked. Gated on
    /// `verified` so it protects a live session but never interrupts the
    /// awaiting-approval poll (which gets no key presses). Pure (takes `now`) so it's
    /// testable without sleeping.
    fn idle_expired(&self, now: Instant) -> bool {
        match self.idle_timeout {
            Some(timeout) if self.verified => now.duration_since(self.last_activity) >= timeout,
            _ => false,
        }
    }

    /// Drop the in-memory identity and all decrypted vault state, wipe the clipboard,
    /// and return to the unlock screen. Used by idle auto-lock.
    fn lock(&mut self) {
        self.identity = None; // StoreState is ZeroizeOnDrop
        self.entries.clear();
        self.detail = None;
        self.groups.clear();
        self.entry_form = None;
        self.group_form = None;
        self.search.clear();
        self.searching = false;
        self.show_help = false;
        self.reveal = false;
        self.verified = false;
        self.busy = false;
        self.input.zeroize();
        self.clipboard.clear();
        self.last_activity = Instant::now();
        self.screen = if self.store.exists() {
            Screen::Unlock
        } else {
            Screen::Enroll
        };
        self.status = Status::warning("Locked after inactivity — enter your passphrase to unlock.");
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
                // Load groups too (quietly) so the new-entry picker is ready.
                vec![
                    Command::LoadPasswords { expired: false },
                    Command::LoadGroups { show: false },
                ]
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
            Message::GroupsLoaded { rows, show } => {
                self.groups = rows;
                if show {
                    self.screen = Screen::Groups;
                    let n = self.groups.len();
                    self.status =
                        Status::info(format!("{n} {}", if n == 1 { "group" } else { "groups" }));
                }
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

            Message::GroupCreated => {
                self.busy = false;
                self.group_form = None;
                self.screen = Screen::Groups;
                self.status = Status::success("Group created.");
                vec![Command::LoadGroups { show: true }]
            }
            Message::EntryCreated => {
                self.busy = false;
                self.entry_form = None;
                self.screen = Screen::Entries;
                self.show_expired = false;
                self.status = Status::success("Entry saved.");
                vec![Command::LoadPasswords { expired: false }]
            }
            Message::WriteFailed(err) => {
                self.busy = false;
                self.status = Status::error(err);
                vec![]
            }

            Message::ClipboardCleared => {
                self.status = Status::info("Clipboard cleared.");
                vec![]
            }
            Message::TokenRefreshed(state) => {
                self.identity = Some(*state);
                self.busy = false;
                self.input.zeroize();
                self.screen = Screen::Entries;
                self.status = Status::success("Device token rotated and saved.");
                vec![]
            }
            Message::RefreshFailed(err) => {
                self.busy = false;
                self.input.zeroize();
                self.status = Status::error(format!("Token refresh failed: {err}"));
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
        // The help overlay swallows the next key press to dismiss itself.
        if self.show_help {
            self.show_help = false;
            return vec![];
        }
        match self.screen {
            Screen::Unlock => self.on_key_unlock(key),
            Screen::Enroll => self.on_key_enroll(key),
            Screen::ReSignPrompt => self.on_key_resign(key),
            Screen::RefreshPrompt => self.on_key_refresh(key),
            Screen::Entries => self.on_key_entries(key),
            Screen::Groups => self.on_key_groups(key),
            Screen::EntryDetail => self.on_key_detail(key),
            Screen::NewEntry => self.on_key_new_entry(key),
            Screen::NewGroup => self.on_key_new_group(key),
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

    /// Indices into [`App::entries`] that match the active search filter.
    pub fn visible_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, row)| entry_matches(row, &self.search))
            .map(|(i, _)| i)
            .collect()
    }

    fn on_key_entries(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.search.clear();
                    self.searching = false;
                    self.selected = 0;
                }
                KeyCode::Enter => self.searching = false,
                KeyCode::Backspace => {
                    self.search.pop();
                    self.selected = 0;
                }
                KeyCode::Char(c) => {
                    self.search.push(c);
                    self.selected = 0;
                }
                _ => {}
            }
            return vec![];
        }
        // Ctrl+R rotates the device token (distinct from `r` = refresh the list).
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
            self.input.clear();
            self.screen = Screen::RefreshPrompt;
            self.status =
                Status::info("Rotate device token — enter your master passphrase to confirm.");
            return vec![];
        }
        match key.code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                vec![]
            }
            KeyCode::Down => {
                if self.selected + 1 < self.visible_indices().len() {
                    self.selected += 1;
                }
                vec![]
            }
            KeyCode::Enter => {
                let target = self
                    .visible_indices()
                    .get(self.selected)
                    .and_then(|&i| self.entries.get(i))
                    .map(|row| row.uuid.clone());
                match target {
                    Some(uuid) => {
                        self.status = Status::info("Loading entry…");
                        vec![Command::LoadEntry { uuid }]
                    }
                    None => vec![],
                }
            }
            KeyCode::Char('/') => {
                self.searching = true;
                self.selected = 0;
                self.status =
                    Status::info("Search — type to filter, Enter to accept, Esc to clear.");
                vec![]
            }
            KeyCode::Char('t') => {
                let expired = !self.show_expired;
                self.status = Status::info("Loading…");
                vec![Command::LoadPasswords { expired }]
            }
            KeyCode::Char('g') => {
                self.status = Status::info("Loading groups…");
                vec![Command::LoadGroups { show: true }]
            }
            KeyCode::Char('n') => self.open_new_entry(),
            KeyCode::Char('r') => {
                let expired = self.show_expired;
                self.status = Status::info("Refreshing…");
                vec![Command::LoadPasswords { expired }]
            }
            KeyCode::Char('?') => {
                self.show_help = true;
                vec![]
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
            KeyCode::Char('n') => {
                self.group_form = Some(GroupForm::blank());
                self.screen = Screen::NewGroup;
                self.status = Status::info("New group — Tab to move, Enter to save.");
                vec![]
            }
            KeyCode::Char('?') => {
                self.show_help = true;
                vec![]
            }
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
            KeyCode::Char('e') => self.open_renew_entry(),
            KeyCode::Char('c') => self.copy_password(),
            KeyCode::Char('u') => self.copy_username(),
            KeyCode::Char('?') => {
                self.show_help = true;
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

    fn copy_password(&mut self) -> Vec<Command> {
        let text = match &self.detail {
            Some(d) => d.secret.password.clone(),
            None => return vec![],
        };
        self.copy_to_clipboard(text, "Password")
    }

    fn copy_username(&mut self) -> Vec<Command> {
        let text = match &self.detail {
            Some(d) => d.secret.username.clone(),
            None => return vec![],
        };
        self.copy_to_clipboard(text, "Username")
    }

    /// Copy `text` to the clipboard and, if a clear window is configured, schedule the
    /// auto-clear. Reports gracefully when no clipboard backend is available.
    fn copy_to_clipboard(&mut self, text: String, label: &str) -> Vec<Command> {
        if text.is_empty() {
            self.status = Status::warning(format!("{label} is empty — nothing to copy."));
            return vec![];
        }
        if !self.clipboard.set(&text) {
            self.status = Status::error("Clipboard unavailable in this environment.");
            return vec![];
        }
        let secs = self.config.clipboard_clear_secs;
        if secs > 0 {
            self.status = Status::success(format!("{label} copied — clears in {secs}s."));
            vec![Command::ClearClipboardAfter { secs }]
        } else {
            self.status = Status::success(format!("{label} copied."));
            vec![]
        }
    }

    fn on_key_refresh(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.busy {
            return vec![];
        }
        match key.code {
            KeyCode::Esc => {
                self.input.zeroize();
                self.screen = Screen::Entries;
                self.status = Status::info("Token rotation cancelled.");
                vec![]
            }
            KeyCode::Enter => {
                if self.input.is_empty() {
                    self.status = Status::warning("Enter your master passphrase to confirm.");
                    return vec![];
                }
                let passphrase = std::mem::take(&mut self.input);
                self.busy = true;
                self.status = Status::info("Rotating token…");
                vec![Command::RefreshToken { passphrase }]
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

    /// Open a blank new-entry form. Requires at least one group to file under.
    fn open_new_entry(&mut self) -> Vec<Command> {
        if self.groups.is_empty() {
            self.status = Status::warning(
                "No groups yet — press g, then n, to create one first (entries need a group).",
            );
            return vec![];
        }
        self.entry_form = Some(EntryForm::blank(0));
        self.screen = Screen::NewEntry;
        self.status = Status::info("New entry — Tab to move, Ctrl+G to generate a password.");
        vec![]
    }

    /// Open the new-entry form pre-filled from the entry on the detail screen.
    /// Saving creates a *new* entry (renew); the old one persists (no update API).
    fn open_renew_entry(&mut self) -> Vec<Command> {
        if self.groups.is_empty() {
            self.status = Status::warning("No groups loaded — press g to load groups, then retry.");
            return vec![];
        }
        let Some(detail) = &self.detail else {
            return vec![];
        };
        // Match the entry's group by name; fall back to the first group.
        let group_idx = detail
            .group
            .as_ref()
            .and_then(|name| self.groups.iter().position(|g| &g.name == name))
            .unwrap_or(0);
        let valid_days = if (MIN_VALID_DAYS..=MAX_VALID_DAYS).contains(&detail.valid_since_days) {
            detail.valid_since_days
        } else {
            DEFAULT_VALID_DAYS
        };
        let s = &detail.secret;
        self.entry_form = Some(EntryForm {
            name: detail.name.clone().unwrap_or_default(),
            username: s.username.clone(),
            password: s.password.clone(),
            url: s.url.clone(),
            notes: s.notes.clone(),
            valid_days: valid_days.to_string(),
            group_idx,
            field: EntryField::Password,
            renewing: true,
        });
        self.screen = Screen::NewEntry;
        self.status =
            Status::info("Renew — saving creates a new entry; the old one remains until expiry.");
        vec![]
    }

    fn on_key_new_entry(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.busy {
            return vec![];
        }
        // Ctrl+G generates a strong password regardless of the focused field.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
            if let Some(form) = &mut self.entry_form {
                form.password.zeroize();
                form.password = crypto::generate_password(GENERATED_PASSWORD_LEN);
                form.field = EntryField::Password;
            }
            self.status = Status::info("Generated a random password.");
            return vec![];
        }
        match key.code {
            KeyCode::Esc => {
                self.entry_form = None;
                self.screen = Screen::Entries;
                vec![]
            }
            KeyCode::Enter => self.submit_new_entry(),
            KeyCode::Tab | KeyCode::Down => {
                if let Some(form) = &mut self.entry_form {
                    form.field = form.field.next();
                }
                vec![]
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(form) = &mut self.entry_form {
                    form.field = form.field.prev();
                }
                vec![]
            }
            KeyCode::Left => {
                let count = self.groups.len();
                if let Some(form) = &mut self.entry_form {
                    if form.field == EntryField::Group && count > 0 {
                        form.group_idx = (form.group_idx + count - 1) % count;
                    }
                }
                vec![]
            }
            KeyCode::Right => {
                let count = self.groups.len();
                if let Some(form) = &mut self.entry_form {
                    if form.field == EntryField::Group && count > 0 {
                        form.group_idx = (form.group_idx + 1) % count;
                    }
                }
                vec![]
            }
            KeyCode::Backspace => {
                if let Some(form) = &mut self.entry_form {
                    if let Some(field) = form.focused_mut() {
                        field.pop();
                    }
                }
                vec![]
            }
            KeyCode::Char(c) => {
                if let Some(form) = &mut self.entry_form {
                    match form.field {
                        // Group is chosen with ←/→; valid-days takes digits only.
                        EntryField::Group => {}
                        EntryField::ValidDays if !c.is_ascii_digit() => {}
                        _ => {
                            if let Some(field) = form.focused_mut() {
                                field.push(c);
                            }
                        }
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }

    /// Validate the new-entry form and, if sound, emit the create command.
    fn submit_new_entry(&mut self) -> Vec<Command> {
        let outcome = {
            let Some(form) = self.entry_form.as_ref() else {
                return vec![];
            };
            validate_entry_form(form, &self.groups)
        };
        match outcome {
            Err(status) => {
                self.status = status;
                vec![]
            }
            Ok((secret, group_id, name, valid_since_days)) => {
                self.busy = true;
                self.status = Status::info("Saving entry…");
                vec![Command::CreateEntry {
                    secret,
                    group_id,
                    name,
                    valid_since_days,
                }]
            }
        }
    }

    fn on_key_new_group(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.busy {
            return vec![];
        }
        match key.code {
            KeyCode::Esc => {
                self.group_form = None;
                self.screen = Screen::Groups;
                vec![]
            }
            KeyCode::Enter => self.submit_new_group(),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                if let Some(form) = &mut self.group_form {
                    form.field = match form.field {
                        GroupField::Name => GroupField::Extra,
                        GroupField::Extra => GroupField::Name,
                    };
                }
                vec![]
            }
            KeyCode::Backspace => {
                if let Some(form) = &mut self.group_form {
                    form.focused_mut().pop();
                }
                vec![]
            }
            KeyCode::Char(c) => {
                if let Some(form) = &mut self.group_form {
                    form.focused_mut().push(c);
                }
                vec![]
            }
            _ => vec![],
        }
    }

    /// Validate the new-group form and, if sound, emit the create command.
    fn submit_new_group(&mut self) -> Vec<Command> {
        let outcome = {
            let Some(form) = self.group_form.as_ref() else {
                return vec![];
            };
            let name = form.name.trim();
            if name.is_empty() {
                Err(Status::warning("Group name can't be empty."))
            } else if name.chars().count() > MAX_GROUP_NAME_LEN {
                Err(Status::warning(format!(
                    "Group name must be ≤{MAX_GROUP_NAME_LEN} characters."
                )))
            } else {
                let extra = if form.extra.trim().is_empty() {
                    None
                } else {
                    Some(form.extra.clone())
                };
                Ok((name.to_string(), extra))
            }
        };
        match outcome {
            Err(status) => {
                self.status = status;
                vec![]
            }
            Ok((name, extra)) => {
                self.busy = true;
                self.status = Status::info("Creating group…");
                vec![Command::CreateGroup { name, extra }]
            }
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
            Command::LoadGroups { show } => {
                let Some((token, _key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    let msg = match vault::list_groups(&client, &token).await {
                        Ok(groups) => Message::GroupsLoaded {
                            rows: groups
                                .into_iter()
                                .map(|g| GroupRow {
                                    uuid: g.uuid,
                                    name: g.name,
                                    extra: g.extra,
                                })
                                .collect(),
                            show,
                        },
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
            Command::CreateGroup { name, extra } => {
                let Some((token, _key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    let msg =
                        match vault::create_group(&client, &token, &name, extra.as_deref()).await {
                            Ok(_) => Message::GroupCreated,
                            Err(e) => Message::WriteFailed(vault_error("create group", &e)),
                        };
                    let _ = tx.send(msg);
                });
            }
            Command::CreateEntry {
                secret,
                group_id,
                name,
                valid_since_days,
            } => {
                let Some((token, key)) = self.session_credentials() else {
                    return;
                };
                self.runtime.spawn(async move {
                    // `secret` is dropped (zeroized) when this task ends.
                    let msg = match secret.seal(&key) {
                        Ok(pwd) => {
                            let req = PwdCreateRequest {
                                pwd,
                                group_id,
                                name,
                                extra: None,
                                valid_since_days: Some(valid_since_days),
                            };
                            match vault::create_password(&client, &token, &req).await {
                                Ok(_) => Message::EntryCreated,
                                Err(e) => Message::WriteFailed(vault_error("create entry", &e)),
                            }
                        }
                        Err(e) => Message::WriteFailed(format!("Couldn't encrypt entry: {e}")),
                    };
                    let _ = tx.send(msg);
                });
            }
            Command::ClearClipboardAfter { secs } => {
                let clipboard = self.clipboard.clone();
                self.runtime.spawn(async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    clipboard.clear();
                    let _ = tx.send(Message::ClipboardCleared);
                });
            }
            Command::RefreshToken { passphrase } => {
                let store = self.store.clone();
                let identity = match &self.identity {
                    Some(state) => state.clone(),
                    None => return,
                };
                self.runtime.spawn(async move {
                    let mut passphrase = passphrase;
                    let outcome = refresh_token(&client, &store, &identity, &passphrase).await;
                    passphrase.zeroize();
                    let msg = match outcome {
                        Ok(state) => Message::TokenRefreshed(Box::new(state)),
                        Err(e) => Message::RefreshFailed(e),
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

/// Validate a [`EntryForm`] against the loaded groups. On success returns the data
/// needed to build a [`Command::CreateEntry`]; on failure, the [`Status`] to show.
fn validate_entry_form(
    form: &EntryForm,
    groups: &[GroupRow],
) -> Result<(PwdSecret, String, Option<String>, i64), Status> {
    if groups.is_empty() {
        return Err(Status::warning(
            "No group to file this under — create a group first.",
        ));
    }
    if form.password.is_empty() {
        return Err(Status::warning(
            "Password can't be empty (press Ctrl+G to generate one).",
        ));
    }
    if form.name.chars().count() > MAX_ENTRY_NAME_LEN {
        return Err(Status::warning(format!(
            "Name must be ≤{MAX_ENTRY_NAME_LEN} characters."
        )));
    }
    let valid_since_days = if form.valid_days.trim().is_empty() {
        DEFAULT_VALID_DAYS
    } else {
        match form.valid_days.trim().parse::<i64>() {
            Ok(d) if (MIN_VALID_DAYS..=MAX_VALID_DAYS).contains(&d) => d,
            _ => {
                return Err(Status::warning(format!(
                    "Valid days must be a number from {MIN_VALID_DAYS} to {MAX_VALID_DAYS}."
                )))
            }
        }
    };
    let group_id = match groups.get(form.group_idx) {
        Some(g) => g.uuid.clone(),
        None => return Err(Status::error("Selected group is no longer available.")),
    };
    let name = if form.name.trim().is_empty() {
        None
    } else {
        Some(form.name.clone())
    };
    let secret = PwdSecret {
        username: form.username.clone(),
        password: form.password.clone(),
        url: form.url.clone(),
        notes: form.notes.clone(),
    };
    Ok((secret, group_id, name, valid_since_days))
}

/// Case-insensitive substring match of `query` against an entry's username/url.
fn entry_matches(row: &EntryRow, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    row.username.to_lowercase().contains(&q) || row.url.to_lowercase().contains(&q)
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

/// Rotate the device token via `/refresh`, then persist the new token to the store.
///
/// `/refresh` is looked up by source IP and returns a fresh raw token; both `token`
/// and `ehlo` in the request are sealed under the shared key. The old token is now
/// invalid, so we must re-encrypt the store under `passphrase` with the new one.
async fn refresh_token(
    client: &ApiClient,
    store: &Store,
    identity: &StoreState,
    passphrase: &str,
) -> Result<StoreState, String> {
    let shared = identity.shared_key();
    let sealed_token = crypto::seal_hex(identity.device_token.as_bytes(), &shared);
    let sealed_ehlo = crypto::seal_hex(identity.ehlo_secret.as_bytes(), &shared);

    let new_token = auth::refresh(client, &sealed_token, &sealed_ehlo)
        .await
        .map_err(|e| e.to_string())?;

    let mut state = identity.clone();
    state.device_token = new_token;

    let to_save = state.clone();
    let store = store.clone();
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
    use std::time::{Duration, Instant};

    fn dummy_state() -> StoreState {
        StoreState {
            client_private: [1u8; 32],
            client_public: [2u8; 32],
            server_public: [3u8; 32],
            device_token: "tok".into(),
            ehlo_secret: "ehlo".into(),
        }
    }

    fn config_in(dir: &Path) -> Config {
        Config {
            api_base_url: "http://localhost:53971".into(),
            request_timeout_secs: 30,
            verify_tls: true,
            data_dir: dir.to_string_lossy().into_owned(),
            clipboard_clear_secs: 30,
            idle_lock_secs: 300,
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
            [
                Command::LoadPasswords { expired: false },
                Command::LoadGroups { show: false }
            ]
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
        assert!(matches!(
            cmds.as_slice(),
            [Command::LoadGroups { show: true }]
        ));
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

    // ---- M5: write ----

    fn group_rows(specs: &[(&str, &str)]) -> Vec<GroupRow> {
        specs
            .iter()
            .map(|(uuid, name)| GroupRow {
                uuid: (*uuid).into(),
                name: (*name).into(),
                extra: None,
            })
            .collect()
    }

    fn press_ctrl(app: &mut App, code: KeyCode) {
        app.handle(Message::Key(KeyEvent::new(code, KeyModifiers::CONTROL)));
    }

    #[test]
    fn entries_n_without_groups_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Char('n'),
            KeyModifiers::NONE,
        )));
        assert!(cmds.is_empty());
        assert_eq!(app.screen, Screen::Entries);
        assert_eq!(app.status.kind, StatusKind::Warning);
        assert!(app.entry_form.is_none());
    }

    #[test]
    fn entries_n_with_groups_opens_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.groups = group_rows(&[("g1", "Work")]);
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::NewEntry);
        assert!(app.entry_form.is_some());
    }

    #[test]
    fn new_entry_ctrl_g_generates_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.entry_form = Some(EntryForm::blank(0));
        press_ctrl(&mut app, KeyCode::Char('g'));
        let form = app.entry_form.as_ref().unwrap();
        assert_eq!(form.password.chars().count(), GENERATED_PASSWORD_LEN);
        assert_eq!(form.field, EntryField::Password);
    }

    #[test]
    fn new_entry_group_picker_cycles() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.groups = group_rows(&[("g1", "Work"), ("g2", "Home")]);
        let mut form = EntryForm::blank(0);
        form.field = EntryField::Group;
        app.entry_form = Some(form);

        press(&mut app, KeyCode::Right);
        assert_eq!(app.entry_form.as_ref().unwrap().group_idx, 1);
        press(&mut app, KeyCode::Right); // wraps back to 0
        assert_eq!(app.entry_form.as_ref().unwrap().group_idx, 0);
    }

    #[test]
    fn new_entry_submit_emits_create_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.groups = group_rows(&[("g1", "Work")]);
        let mut form = EntryForm::blank(0);
        form.password = "s3cr3t".into();
        form.username = "alice".into();
        app.entry_form = Some(form);

        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(matches!(
            cmds.as_slice(),
            [Command::CreateEntry { group_id, secret, valid_since_days, .. }]
                if group_id == "g1" && secret.password == "s3cr3t" && *valid_since_days == 30
        ));
        assert!(app.busy);
    }

    #[test]
    fn new_entry_empty_password_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.groups = group_rows(&[("g1", "Work")]);
        app.entry_form = Some(EntryForm::blank(0)); // password empty

        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn new_entry_invalid_valid_days_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.groups = group_rows(&[("g1", "Work")]);
        let mut form = EntryForm::blank(0);
        form.password = "x".into();
        form.valid_days = "999".into(); // > MAX_VALID_DAYS
        app.entry_form = Some(form);

        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn detail_e_opens_prefilled_renew() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::EntryDetail;
        app.groups = group_rows(&[("g1", "Work"), ("g2", "Home")]);
        app.detail = Some(DetailView {
            name: Some("GitHub".into()),
            group: Some("Home".into()),
            expires: 5,
            valid_since_days: 60,
            created_at: "2026-06-01".into(),
            secret: PwdSecret {
                username: "alice".into(),
                password: "old-pw".into(),
                url: "https://github.com".into(),
                notes: String::new(),
            },
        });

        press(&mut app, KeyCode::Char('e'));
        assert_eq!(app.screen, Screen::NewEntry);
        let form = app.entry_form.as_ref().unwrap();
        assert!(form.renewing);
        assert_eq!(form.password, "old-pw");
        assert_eq!(form.group_idx, 1); // matched "Home"
        assert_eq!(form.valid_days, "60");
    }

    #[test]
    fn groups_n_opens_group_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Groups;
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::NewGroup);
        assert!(app.group_form.is_some());
    }

    #[test]
    fn new_group_submit_emits_create_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewGroup;
        let mut form = GroupForm::blank();
        form.name = "Personal".into();
        app.group_form = Some(form);

        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(matches!(
            cmds.as_slice(),
            [Command::CreateGroup { name, extra: None }] if name == "Personal"
        ));
        assert!(app.busy);
    }

    #[test]
    fn new_group_empty_name_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewGroup;
        app.group_form = Some(GroupForm::blank());
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn group_created_reloads_and_returns_to_groups() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewGroup;
        app.group_form = Some(GroupForm::blank());
        let cmds = app.update(Message::GroupCreated);
        assert_eq!(app.screen, Screen::Groups);
        assert!(app.group_form.is_none());
        assert!(matches!(
            cmds.as_slice(),
            [Command::LoadGroups { show: true }]
        ));
    }

    #[test]
    fn entry_created_reloads_valid_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::NewEntry;
        app.show_expired = true;
        app.entry_form = Some(EntryForm::blank(0));
        let cmds = app.update(Message::EntryCreated);
        assert_eq!(app.screen, Screen::Entries);
        assert!(app.entry_form.is_none());
        assert!(!app.show_expired);
        assert!(matches!(
            cmds.as_slice(),
            [Command::LoadPasswords { expired: false }]
        ));
    }

    // ---- M6: secure copy & polish ----

    #[test]
    fn search_filters_by_username() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.entries = rows(&[("a", "alice"), ("b", "bob"), ("c", "alistair")]);
        app.search = "ali".into();
        assert_eq!(app.visible_indices(), vec![0, 2]);
    }

    #[test]
    fn entries_slash_enters_search_then_esc_clears() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.entries = rows(&[("a", "alice"), ("b", "bob")]);

        press(&mut app, KeyCode::Char('/'));
        assert!(app.searching);
        press(&mut app, KeyCode::Char('b'));
        assert_eq!(app.search, "b");
        assert_eq!(app.visible_indices(), vec![1]);
        press(&mut app, KeyCode::Esc);
        assert!(!app.searching);
        assert!(app.search.is_empty());
    }

    #[test]
    fn enter_opens_uuid_from_filtered_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        app.entries = rows(&[("a", "alice"), ("b", "bob")]);
        app.search = "bob".into();
        // Filtered list has one row (bob) at index 0.
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(matches!(cmds.as_slice(), [Command::LoadEntry { uuid }] if uuid == "b"));
    }

    #[test]
    fn help_opens_and_any_key_closes() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        press(&mut app, KeyCode::Char('?'));
        assert!(app.show_help);
        press(&mut app, KeyCode::Down); // any key dismisses
        assert!(!app.show_help);
    }

    #[test]
    fn idle_expired_needs_verified_and_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.idle_timeout = Some(Duration::ZERO);

        app.verified = false; // e.g. still awaiting approval — never auto-lock
        assert!(!app.idle_expired(Instant::now()));

        app.verified = true; // live vault session
        assert!(app.idle_expired(Instant::now()));

        app.idle_timeout = None; // disabled
        assert!(!app.idle_expired(Instant::now()));
    }

    #[test]
    fn lock_wipes_state_and_returns_to_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&config_in(dir.path()));
        std::fs::write(store.path(), b"PWMS-pretend-store").unwrap();
        let mut app = app_in(dir.path());

        app.identity = Some(dummy_state());
        app.verified = true;
        app.entries = rows(&[("a", "alice")]);
        app.search = "x".into();
        app.screen = Screen::Entries;

        app.lock();
        assert!(app.identity.is_none());
        assert!(app.entries.is_empty());
        assert!(!app.verified);
        assert!(app.search.is_empty());
        assert_eq!(app.screen, Screen::Unlock);
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn ctrl_r_opens_refresh_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::Entries;
        press_ctrl(&mut app, KeyCode::Char('r'));
        assert_eq!(app.screen, Screen::RefreshPrompt);
    }

    #[test]
    fn refresh_prompt_enter_emits_refresh_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::RefreshPrompt;
        type_str(&mut app, "masterpw");
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert!(
            matches!(cmds.as_slice(), [Command::RefreshToken { passphrase }] if passphrase == "masterpw")
        );
        assert!(app.busy);
        assert!(app.input.is_empty());
    }

    #[test]
    fn copy_empty_password_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        app.screen = Screen::EntryDetail;
        app.detail = Some(DetailView {
            name: None,
            group: None,
            expires: 1,
            valid_since_days: 30,
            created_at: String::new(),
            secret: PwdSecret::default(), // empty password
        });
        let cmds = app.update(Message::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE,
        )));
        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Warning);
    }

    #[test]
    fn clipboard_cleared_sets_status() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app_in(dir.path());
        let cmds = app.update(Message::ClipboardCleared);
        assert!(cmds.is_empty());
        assert_eq!(app.status.kind, StatusKind::Info);
    }
}
