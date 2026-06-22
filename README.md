# password-manager-terminal

A terminal (TUI) client for a zero-knowledge password-manager backend, built with
[ratatui](https://ratatui.rs). Secrets are sealed and opened **client-side** with
X25519 ECDH + AES-256-GCM; the server only ever stores ciphertext. Long-lived
credentials live in an encrypted local store, unlocked with a master passphrase.

## Build & run

```sh
cp .env.example .env      # adjust PWM_API_BASE_URL etc. (no secrets go here)
cargo run                 # release: cargo run --release
```

Quality gate used throughout development:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

To exercise the TUI end-to-end against a running backend (enrollment, device
approval, re-sign, refresh) and for the state-reset gotchas, see
[`docs/testing.md`](docs/testing.md).

## First run & the session flow

1. **Enroll** — with no local store, enter your account **name**, **ehlo** secret,
   and a local **master passphrase**. The app generates an X25519 keypair, greets the
   server, then **signs up** (new account) or **signs in** (existing one — toggle with
   `Ctrl+T`) with the sealed name + ehlo, stores the server-issued device token, and
   waits. A taken name on sign-up auto-switches to sign-in.
2. **Awaiting approval** — an administrator must approve the device out of band; the
   app polls until it's approved.
3. **Unlock** — on later runs, your passphrase decrypts the local store and the app
   verifies the session. If your IP changed, it offers **re-sign** (needs re-approval).
4. **Vault** — browse groups and entries, view/copy secrets, and create new ones.

## Keybindings

Navigation is arrow/letter style (`Esc` goes back or quits).

| Screen | Keys |
|--------|------|
| **Enroll** | `Tab`/`↑↓` move fields · `Ctrl+T` create-account/sign-in · `Enter` submit · `Esc` quit |
| **Entries** | `↑`/`↓` move · `Enter` open · `n` new · `/` search · `t` valid/expired · `g` groups · `r` refresh · `Ctrl+R` rotate device token · `?` help · `q` quit |
| **Entry detail** | `s` reveal/hide password · `c` copy password · `u` copy username · `e` renew · `Esc` back |
| **New entry** | `Tab`/`↑↓` move fields · `←`/`→` pick group · `Ctrl+G` generate password · `Enter` save · `Esc` cancel |
| **Groups** | `n` new group · `Esc` back |
| **Re-sign / Refresh** | follow the on-screen prompt |

Notes:

- **Renew, not edit.** The backend has no update or delete endpoint, so renewing an
  entry creates a *new* one (the original persists until it expires).
- **Copied secrets auto-clear** from the clipboard after `PWM_CLIPBOARD_CLEAR_SECS`.
- **Idle auto-lock** drops the in-memory identity after `PWM_IDLE_LOCK_SECS` of
  inactivity and returns to the unlock screen.

## Configuration

All settings come from the environment (or `.env`); see [`.env.example`](.env.example).

| Variable | Default | Meaning |
|----------|---------|---------|
| `PWM_API_BASE_URL` | `http://localhost:53971` | Backend base URL (no trailing slash) |
| `PWM_REQUEST_TIMEOUT_SECS` | `30` | HTTP request timeout |
| `PWM_VERIFY_TLS` | `true` | Verify TLS certificates |
| `PWM_DATA_DIR` | `~/.pwd-manager` | Where the encrypted local store lives |
| `PWM_CLIPBOARD_CLEAR_SECS` | `30` | Seconds before copied secrets are wiped |
| `PWM_IDLE_LOCK_SECS` | `300` | Idle seconds before auto-lock (`0` disables) |

## Security model

- The master passphrase is never stored; the local store is encrypted with an
  Argon2id-derived key and written `0600`.
- In-memory secrets (`StoreState`, decrypted entries, form fields) are zeroized on
  drop; passphrase fields are wiped on quit.
- `name`/`extra` fields are **plaintext** on the server by design — never put secrets
  there. Only the `pwd` blob (`{username, password, url, notes}`) is sealed.
- Clipboard contents are inherently exposed to the OS while present; the auto-clear
  timer limits the window. A native clipboard (`arboard`) is used when available and
  degrades gracefully (with a status message) in headless/SSH sessions.
