# password-manager-terminal

A terminal (TUI) client for a zero-knowledge password-manager backend, built with
[ratatui](https://ratatui.rs). Secrets are sealed and opened **client-side** with
X25519 ECDH + AES-256-GCM; the server only ever stores ciphertext. Long-lived
credentials live in an encrypted local store, unlocked with a master passphrase.

Runs on **Linux** and **Windows** (and macOS). Most users should grab a prebuilt
installer (no Rust toolchain needed); building from source is also supported.

## Install

Two ways to install — pick the **packaged installer** unless there's none for your
platform, in which case build from source.

### Packaged installer (recommended — no toolchain)

Download the latest `.deb` or `.msi` from the
[**latest release**](https://github.com/karatay-lab/password-manager-terminal/releases/latest):

- **Linux (Debian/Ubuntu & derivatives):** grab the `.deb`, then from your download
  directory (the `*` matches whichever version you downloaded):

  ```sh
  sudo apt install ./pwd-manager-terminal_*_amd64.deb   # resolves deps
  # or: sudo dpkg -i ./pwd-manager-terminal_*_amd64.deb
  ```

  Installs `pwd-manager-terminal` to `/usr/bin` (already on `PATH`); a sample config
  lands at `/usr/share/doc/pwd-manager-terminal/env.example`.

- **Windows:** download and run the `.msi` (`pwd-manager-terminal-*-x86_64.msi`), then
  follow the wizard. It installs into *Program Files* and offers to add itself to
  `PATH`. Uninstall via *Settings → Apps → Installed apps*.

Then [configure](#configure) and run `pwd-manager-terminal`.

### Build from source

Requires a recent **stable Rust toolchain** via [rustup](https://rustup.rs) — the
only hard build dependency, since the client is `rustls`-based (**no OpenSSL/system
TLS libraries**). On Windows use the default MSVC toolchain
(`rustup default stable-msvc`) plus the C++ Build Tools rustup prompts for.

```sh
git clone https://github.com/karatay-lab/password-manager-terminal.git
cd password-manager-terminal
cargo install --path .        # installs `pwd-manager-terminal` onto your PATH
# …or `cargo build --release` and run ./target/release/pwd-manager-terminal[.exe]
```

> **Linux clipboard:** copy/paste needs a running **X11 or Wayland** session at
> runtime. In a headless/SSH session the app still works — it just reports that the
> clipboard is unavailable instead of copying.

### Configure

The app reads settings from **environment variables** and from `.env` files, merged
at startup in this precedence (highest first):

1. Real environment variables already set in your shell.
2. `./.env` — the directory you launch from (handy for development).
3. `~/.config/pwd-manager-terminal/.env` — per-user
   (`%APPDATA%\pwd-manager-terminal\.env` on Windows; honours `$XDG_CONFIG_HOME`).
4. `/etc/pwd-manager-terminal/.env` — system-wide (Linux/macOS).

Copy the template into whichever location suits you and point it at your backend:

```sh
mkdir -p ~/.config/pwd-manager-terminal
cp .env.example ~/.config/pwd-manager-terminal/.env   # then edit PWM_API_BASE_URL
# (from a .deb install, the template is /usr/share/doc/pwd-manager-terminal/env.example)
```

At minimum set **`PWM_API_BASE_URL`**. See [Configuration](#configuration) for the
full list of variables.

> **Windows data-dir note.** The default `PWM_DATA_DIR=~/.pwd-manager` only expands
> when a `HOME` variable is set, which Windows usually does **not** have. On Windows,
> set `PWM_DATA_DIR` to an **absolute path** — e.g. `C:\Users\<you>\.pwd-manager` —
> or define `HOME`. Otherwise the store lands in a literal `~` folder under your
> current directory.

### Run

```sh
pwd-manager-terminal
```

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
4. **Vault** — browse groups and entries, view/copy/edit secrets, and create new ones.

## Keybindings

Navigation is arrow/letter style (`Esc` goes back or quits).

| Screen | Keys |
|--------|------|
| **Enroll** | `Tab`/`↑↓` move fields · `Ctrl+T` create-account/sign-in · `Enter` submit · `Esc` quit |
| **Entries** | `↑`/`↓` move · `Enter` open · `n` new · `/` search · `t` valid/expired · `g` groups · `r` refresh · `Ctrl+R` rotate device token · `?` help · `q` quit |
| **Entry detail** | `s` reveal/hide password · `c` copy password · `u` copy username · `e` edit in place · `Esc` back |
| **New / edit entry** | `Tab`/`↑↓` move fields · `←`/`→` pick group · `Ctrl+G` generate password · `Enter` save · `Esc` cancel |
| **Groups** | `n` new group · `Esc` back |
| **Re-sign / Refresh** | follow the on-screen prompt |

Notes:

- **Edit vs. create.** `e` on an entry opens a prefilled form that overwrites that
  entry **in place** (`PUT /pwd/update`), leaving its expiry window unchanged.
  Creating a new entry (`n`) always makes a fresh row. There is **no delete
  endpoint** — entries persist on the server until they expire.
- **Copied secrets auto-clear** from the clipboard after `PWM_CLIPBOARD_CLEAR_SECS`.
- **Idle auto-lock** drops the in-memory identity after `PWM_IDLE_LOCK_SECS` of
  inactivity and returns to the unlock screen.

## Reset & re-authenticate

All long-lived state lives in **one encrypted file**: `store.enc` inside
`PWM_DATA_DIR` (default `~/.pwd-manager`, created `0700`; the file is `0600`). It
holds the device keypair, the server's public key, the device token, and your
account name/ehlo. Knowing this makes reset trivial.

**Reset (start over from enrollment).** Use this if you forgot the master passphrase,
the store is corrupt, or you want to re-enroll a fresh device/account. Delete the
store, then relaunch — the app will drop you back at the **Enroll** screen.

```sh
# Linux / macOS
rm -f ~/.pwd-manager/store.enc          # or: rm -rf ~/.pwd-manager  (wipe everything)

# Windows (PowerShell) — use your actual PWM_DATA_DIR
Remove-Item -Force "$env:USERPROFILE\.pwd-manager\store.enc"
```

**Re-authenticate.** Pick the lightest option that fits the situation:

| Situation | What to do |
|-----------|------------|
| Normal daily use | Launch and **Unlock** with your master passphrase. |
| Network/IP changed | The app offers **re-sign** at unlock; accept it, then wait for admin re-approval. |
| Rotate a leaked/old device token | On the **Entries** screen press `Ctrl+R` (refresh) — issues a new token and re-encrypts the store. |
| Lost passphrase, corrupt store, or new device | **Reset** (above), then **Enroll** again — sign in to your existing account (or sign up) and have an admin approve the device. |

> Resetting only clears **local** state. The device stays enrolled on the backend
> until an administrator revokes/unconfirms it, and re-enrolling a new device always
> requires a fresh admin approval.

## Uninstall

1. Quit the app.
2. Remove the program, by how you installed it:
   - **`.deb`:** `sudo apt remove pwd-manager-terminal` (or `sudo dpkg -r pwd-manager-terminal`).
   - **`.msi`:** *Settings → Apps → Installed apps → pwd-manager-terminal → Uninstall*.
   - **`cargo install`:** `cargo uninstall pwd-manager-terminal`.
   - **Built in place:** delete `target/release/pwd-manager-terminal[.exe]` (or the
     whole checkout).
3. Delete local state and any config to leave nothing behind:

   ```sh
   # Linux / macOS
   rm -rf ~/.pwd-manager ~/.config/pwd-manager-terminal
   sudo rm -rf /etc/pwd-manager-terminal      # only if you created a system config
   rm -f .env

   # Windows (PowerShell)
   Remove-Item -Recurse -Force "$env:USERPROFILE\.pwd-manager", "$env:APPDATA\pwd-manager-terminal"
   ```

4. **Optional but recommended:** ask an administrator to revoke this device on the
   backend — uninstalling locally does not remove the server-side enrollment.

## Configuration

All settings come from the environment (or one of the layered `.env` files described
under [Configure](#configure)); see [`.env.example`](.env.example).

| Variable | Default | Meaning |
|----------|---------|---------|
| `PWM_API_BASE_URL` | `http://localhost:53971` | Backend base URL (no trailing slash) |
| `PWM_REQUEST_TIMEOUT_SECS` | `30` | HTTP request timeout |
| `PWM_VERIFY_TLS` | `true` | Verify TLS certificates |
| `PWM_DATA_DIR` | `~/.pwd-manager` | Where the encrypted local store lives (see the Windows note under [Configure](#configure)) |
| `PWM_CLIPBOARD_CLEAR_SECS` | `30` | Seconds before copied secrets are wiped |
| `PWM_IDLE_LOCK_SECS` | `300` | Idle seconds before auto-lock (`0` disables) |

## Security model

- The master passphrase is never stored; the local store is encrypted with an
  Argon2id-derived key and written `0600` (the data dir is `0700`).
- In-memory secrets (`StoreState`, decrypted entries, form fields) are zeroized on
  drop; passphrase fields are wiped on quit.
- `name`/`extra` fields are **plaintext** on the server by design — never put secrets
  there. Only the `pwd` blob (`{username, password, url, notes}`) is sealed.
- Clipboard contents are inherently exposed to the OS while present; the auto-clear
  timer limits the window. A native clipboard (`arboard`) is used when available and
  degrades gracefully (with a status message) in headless/SSH sessions.

## Design docs

For reviewers who want the full picture of how this client was designed and built,
the original v1 design lives under [`v1/`](v1/):

- [`v1/plan.md`](v1/plan.md) — the architecture/plan working draft: what the backend
  is, the crypto + wire model, screen flow, and the module layout the client follows.
- [`v1/terminal-ui.md`](v1/terminal-ui.md) — the full screen-by-screen UI spec
  (sign-in, vault, entry), global conventions, keybindings, and the navigation map.

> These are the **v1 design drafts** and predate the backend's move from `/register`
> to the **sign-up / sign-in** credential model — read them for intent and structure,
> but treat this README and the code as the source of truth for current behaviour.

## Development

Quality gate used throughout development:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

To exercise the TUI end-to-end against a running backend (enrollment, device
approval, re-sign, refresh) and for the state-reset gotchas, see
[`docs/testing.md`](docs/testing.md).
