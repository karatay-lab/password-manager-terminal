# pwd-manager-terminal — v1 plan (working draft)

> Status: **DRAFT — we build this together.**
> Sections marked **❓DECIDE** are open questions for us.
> Crypto/wire details are now **VERIFIED from backend source** — see
> [`docs/protocol-notes.md`](../docs/protocol-notes.md) (ground truth; `api.md` has
> a few inaccuracies noted there).

A terminal password manager: a Rust + ratatui TUI client for the backend
described in [`docs/protocol-notes.md`](../docs/protocol-notes.md). The backend is
**zero-knowledge-ish**: the client holds the keys, encrypts secrets locally with an
X25519-ECDH-derived key, and the server only ever stores ciphertext.

---

## 1. What the backend actually is (recap from api.md)

- **No username/password login.** Identity = an approved **device token**, bound to
  the client's source **IP**, established via an X25519 key-exchange handshake.
- **Client-side crypto is mandatory.** Client ⇄ server payloads (`token`, `ehlo`,
  `pwd`) are AES-256-GCM encrypted with a key derived from X25519 ECDH.
- **Admin approval gate.** After `/register`, `is_confirmed=false` until an admin
  approves out of band. Nothing works until then.
- **Organization:** `groups` (not folders). Passwords belong to a group.
- **Expiry:** entries carry `valid_since_days` (1–365); the API exposes separate
  valid/expired lists. Entries "expire" — renewing = update.
- **No password DELETE endpoint.** v1 can create / read / update only.
- **Auth header:** `device-token: <raw token>` on all CRUD; `admin-*` endpoints are
  out of scope for this client.

## 2. Goal & scope (v1)

Must-have:

- First-run **enrollment**: keygen → `/greet` → `/register` → wait for approval.
- **Unlock** an existing local identity and `/verify` (with `/re-sign` fallback on
  IP change).
- **Groups:** list, create.
- **Passwords:** list valid + expired, view one (decrypted), create, update (= renew).
- **Copy** username/password to clipboard with auto-clear.
- **Search/filter** entries; clean lock/quit that wipes secrets from memory.

**❓DECIDE — v1 cuts:** which of {create group in-app, expired-list view, password
generator, token `/refresh` UI, search} ship in v1 vs v2?

## 3. Non-goals for v1

- Admin endpoints (approval, identity management).
- Deleting passwords (no backend endpoint).
- Multi-identity / multi-device on one machine.
- Offline editing & sync reconciliation.

## 4. The crypto model (the heart of this app)

> **VERIFIED — full exact spec + crypto code to port is in
> [`docs/protocol-notes.md`](../docs/protocol-notes.md).** Summary below.

```
ENROLL (first run)
  client: gen X25519 keypair (priv_c, pub_c)         clamp like x25519-dalek
  client: pick device_token (any utf8 str) + ehlo_secret (any utf8 str)
  ── POST /greet { pub_key: hex(pub_c) } ──▶
  ◀── { server_public_key: hex(pub_s) } ──
  client: shared = x25519(priv_c, pub_s)   ← RAW 32B == AES-256 key, no KDF
  ── POST /register { token: seal(token), ehlo: seal(ehlo) } ──▶  (seal = hex(nonce12‖ct‖tag))
  ◀── 200 null ── (is_confirmed=false → wait for admin approval)

EVERY SESSION
  unlock local store → re-derive `shared` from priv_c + pub_s
  ── GET /verify  (device-token: raw token) ──▶ 200 ok | 401
        on 401 (likely IP change): POST /re-sign { token: hex(RAW token), ehlo: seal(ehlo) }
                                   (⚠️ re-sign token is NOT sealed; resets is_confirmed)

PASSWORD READ/WRITE
  create: pwd = seal(plaintext_json) → POST /pwd/create
  read:   GET /pwd/get/{uuid} → pwd field = sealed → open(pwd, shared)
```

**Local persistent store** (encrypted at rest — see §6), all SECRET:
`priv_c`, `pub_c`, `pub_s` (server pub from greet), `device_token`, `ehlo_secret`.
(`shared` is re-derivable; don't persist it.)

**Resolved interop facts** (were the old blockers): key = raw X25519 secret (no
HKDF); wire = `nonce(12)‖ct‖tag` hex, no AAD; `pwd` plaintext is **client-defined**
(seal a JSON blob `{username,password,url,notes}`); `name`/`extra` are server-side
**plaintext**; initial `device_token` is **client-chosen** (refresh rotates it to a
UUID). We port `src/bin/test_sender.rs` directly.

## 5. Architecture (proposed: The Elm Architecture)

```
            ┌────────────┐   Message    ┌──────────┐
 input ────▶│ event loop  │────────────▶│  update  │── command ──▶ async/worker
 (crossterm)│ (main thread)│◀────────────│ (state)  │◀── result ──┘ (api + crypto)
            └─────┬───────┘   redraw     └────┬─────┘
                  ▼ view(state)                ▼ owns
            ratatui Frame                  AppState (Model)
```

- All network + crypto runs **off the UI thread**; results return as `Message`s.
- `view` is pure; `update` mutates Model and may emit commands.

**❓DECIDE — async vs threads:** `tokio` + `reqwest` (async) **or** worker thread +
blocking `ureq`? (Crypto/argon2 is CPU-bound either way → run on a blocking task/
thread regardless.)

## 6. Local credential store & unlock

The device token + X25519 private key are long-lived secrets that must survive
restarts but never sit in plaintext on disk.

**❓DECIDE — store strategy:**
- **A) OS keyring** (`keyring` crate): no app passphrase, relies on the OS session.
- **B) Passphrase-encrypted file** (`argon2` → key → AES-256-GCM file in
  `PWM_DATA_DIR`): a local "master password" unlocks the app each launch.
- **C) Both:** keyring by default, passphrase fallback on headless boxes.

Either way: `secrecy::SecretString` in memory, `zeroize` on drop, no logging of
secrets, clipboard auto-clear (`PWM_CLIPBOARD_CLEAR_SECS`, default 30s).
**❓DECIDE:** idle auto-lock in v1 or v2?

## 7. Proposed module layout

```
src/
  main.rs            # load .env/config, init terminal, run loop, restore
  app.rs             # App (Model), Screen enum, run loop
  message.rs         # Message / Action enum (input + async results)
  update.rs          # update(app, msg) -> Option<Command>
  config.rs          # env + CLI + file config (precedence)
  store.rs           # encrypted local credential store (load/unlock/save)
  crypto.rs          # X25519 ECDH + AES-256-GCM seal/open + hex (port test_sender.rs)
  clipboard.rs       # copy with auto-clear timeout
  api/
    mod.rs           # client + endpoint methods
    auth.rs          # greet, register, verify, re-sign, refresh
    models.rs        # serde request/response types
    error.rs         # ApiError (thiserror) mapped from status codes
  ui/
    mod.rs           # view(app, frame) dispatch by Screen
    enroll.rs        # first-run handshake + "awaiting approval"
    unlock.rs        # unlock local store
    groups.rs        # group list / create
    entries.rs       # password list (valid/expired), search
    entry_detail.rs  # decrypted view, copy actions
    entry_edit.rs    # create / update (renew) form
    components.rs     # status bar, popup, input field, help
```

## 8. Screens / flows (v1)

> Full screen-by-screen UI design (mockups, keys, API mapping) lives in
> [`terminal-ui.md`](./terminal-ui.md). Summary below.

1. **Enroll** (no local identity yet): generate keys, `/greet`, `/register`, then an
   **"awaiting admin approval"** screen that polls `/verify`.
2. **Unlock** (identity exists): passphrase/keyring → `/verify` (→ `/re-sign` on 401).
3. **Groups:** list; `n` new group.
4. **Entries:** list valid (toggle to expired); `/` search, `Enter` open, `n` new,
   show expiry/“expires in N days”.
5. **Entry detail:** decrypted fields; `c` copy password, `u` copy username, `e` edit.
6. **Entry edit:** form → seal `pwd` → create or update. ⚠️ `update` does **not**
   reset expiry (no `created_at`/`valid_since_days` change server-side); to **renew**
   an expiring entry, **create a new one** (old persists — no delete endpoint).
7. **Status/help bar:** keybindings + transient errors (map generic `401 unauthorized`
   to a helpful "device not approved / IP changed?" hint).

**❓DECIDE — keymap:** vim-style (`hjkl`, `:`) or arrow/letter style?

## 9. Error handling specifics

- `ApiError` (thiserror) maps documented statuses: 400 bad input, 401 unauthorized
  (generic — could be unconfirmed / wrong IP / bad token), 404, 409, 412 (greet
  already exists), 500. The backend deliberately returns generic `"unauthorized"`,
  so the UI must guide the user (e.g. "not yet approved by admin, or your IP
  changed — try re-sign").
- Respect **rate limits** (greet/register 2 rps; verify/CRUD 10 rps; admin 5 rps):
  debounce polling on the approval screen.

## 10. Milestones

- **M0 — scaffold:** `cargo init`, deps, `ratatui::init/restore`, empty loop quitting
  on `q`, terminal restored on panic. Config + `.env` loading.
- **M1 — crypto core:** `crypto.rs` (port `test_sender.rs`) + a round-trip test, and
  ideally an integration test that seals→sends→reads back against a local backend.
- **M2 — enrollment:** greet → register → approval-poll → store persisted/encrypted.
- **M3 — session:** unlock store, verify, re-sign fallback.
- **M4 — read:** groups list, pwd list (valid/expired), get + decrypt + detail view.
- **M5 — write:** create + update + group create (renew = create-new, see §8).
- **M6 — secure copy & polish:** clipboard auto-clear, zeroize audit, search, help,
  error hints, usage docs.

## 11. Open questions (consolidated)

- [x] ~~Crypto/wire interop~~ — **RESOLVED** from backend source (`docs/protocol-notes.md`).
- [ ] v1 scope cuts (§2)
- [ ] async (tokio) vs threads (§5)
- [ ] local store: keyring vs passphrase vs both (§6)
- [ ] idle auto-lock in v1? (§6)
- [ ] keymap style (§8)
- [ ] `pwd` JSON schema fields — confirm `{username,password,url,notes}` is what we want.

---

### Next step

Crypto is unblocked. Pick the
**❓DECIDE** defaults and lock M0's `Cargo.toml` + skeleton.
