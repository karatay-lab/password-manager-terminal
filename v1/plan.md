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

**✅ DECIDED (M2) — async:** `tokio` + `reqwest` (rustls). The api layer is `async`;
results return to the UI thread as `Message`s. (Crypto/argon2 is CPU-bound → run on a
blocking task/thread regardless.)

## 6. Local credential store & unlock

The device token + X25519 private key are long-lived secrets that must survive
restarts but never sit in plaintext on disk.

**✅ DECIDED (M2) — store strategy: B) Passphrase-encrypted file.** Master passphrase
→ Argon2id → AES-256-GCM file (`<PWM_DATA_DIR>/store.enc`, `0600`). Chosen over the OS
keyring (A) because the target runs **headless** — no Secret Service to rely on — and
this is the conventional model for a password manager. Implemented in `src/store.rs`.
- ~~A) OS keyring~~ — needs an OS session/Secret Service; absent on headless boxes.
- ~~C) Both~~ — more code paths than v1 needs; revisit if a desktop build appears.

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

**✅ DECIDED (M3) — keymap: arrow/letter style.** Arrows/Enter to navigate, `Esc`
to go back/quit, single-letter actions (`n` new, `e` edit, `c` copy, `r` re-sign,
`w` wait). Lower learning curve than vim-style for the target users.

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
  - ✅ `src/api/` (reqwest client, `auth::{greet,register,verify}`, models, error mapping)
    and `src/store.rs` (Argon2id + AES-256-GCM, `0600`, atomic write, zeroize) landed
    with unit tests. **Remaining for M3:** wire the tokio runtime + the enroll/approval
    *screen* (UI + message/command plumbing) that drives these against a live backend.
- **M3 — session:** unlock store, verify, re-sign fallback.
  - ✅ tokio runtime wired into the app as a sync-UI/async-task bridge (`Message`/
    `Command` channel; `update` is pure-ish and unit-tested). Screens: **Enroll**
    (passphrase → keygen → greet/register → save), **Awaiting approval** (debounced
    `/verify` poll), **Unlock** (passphrase → decrypt → `/verify`), and a **Re-sign
    prompt** on 401 (drives `auth::re_sign`). `crypto::random_token`,
    `auth::re_sign` + `ReSignRequest` landed. **Pending:** end-to-end run against a
    live backend (no backend available in dev here) — logic is unit-tested only.
- **M4 — read:** groups list, pwd list (valid/expired), get + decrypt + detail view.
  - ✅ `api::vault` (`list_groups`, `list_passwords{valid,expired}`, `get_password`)
    + DTOs (`GroupSummary`, `PwdListItem`, `PwdDetail`). `crate::secret::PwdSecret`
    (`{username,password,url,notes}`, zeroize-on-drop) seals/opens the `pwd` blob.
    Screens: **Entries** (valid/expired toggle, ↑/↓ + Enter, refresh), **Entry
    detail** (decrypted fields; `s` reveal/hide password), **Groups** (read-only
    list). 401 on a vault read maps to an actionable hint. **Deferred:** list
    pagination, and copy-to-clipboard (→ M6). End-to-end vs a live backend pending.
- **M5 — write:** create entry + create group (renew = create-new, see §8).
  - ✅ `api::vault::{create_group, create_password}` + request DTOs (`GroupCreateRequest`,
    `PwdCreateRequest`; `None` fields omitted so the server applies defaults).
    `crypto::generate_password` (rejection-sampled, no modulo bias). Screens: **New
    entry** (name/group-picker/username/password/url/notes/valid-days; `Ctrl+G`
    generates; password reveals only while focused; zeroized on drop) and **New
    group** (name/extra). `n` opens the form on Entries/Groups; **`e` on detail =
    pre-filled renew → fresh `POST /pwd/create`** (the old row persists). Validation:
    non-empty password, `valid_since_days` 1–365 (def 30), name ≤256, group ≤128.
  - ⚠️ **No update/delete endpoint exists** (verified table is create-only) — "edit"
    is always a new create. **Deferred:** copy-to-clipboard, search (→ M6).
    End-to-end vs a live backend still pending.
- **M6 — secure copy & polish:** clipboard auto-clear, zeroize audit, search, help,
  error hints, usage docs.

## 11. Open questions (consolidated)

- [x] ~~Crypto/wire interop~~ — **RESOLVED** from backend source (`docs/protocol-notes.md`).
- [x] ~~async (tokio) vs threads~~ — **DECIDED (M2): tokio + reqwest** (§5).
- [x] ~~local store: keyring vs passphrase vs both~~ — **DECIDED (M2): passphrase + Argon2id** (§6).
- [x] ~~keymap style~~ — **DECIDED (M3): arrow/letter style** (§8).
- [x] ~~`pwd` JSON schema fields~~ — **DECIDED (M4): `{username,password,url,notes}`**
  (`crate::secret::PwdSecret`); `name`/`extra` stay server-plaintext, no secrets there.
- [x] ~~password generator in v1?~~ — **DECIDED (M5): yes**, in the new-entry form (`Ctrl+G`).
- [ ] v1 scope cuts (§2) — remaining open: token `/refresh` UI, search (→ M6).
- [ ] idle auto-lock in v1? (§6)

---

### Next step

M0–M5 landed (scaffold, crypto core, enrollment, session loop, read-side vault, and
write-side: new-entry/new-group forms, password generator, renew-as-new-create).
**M6 — secure copy & polish:** clipboard copy of username/password with auto-clear
(`Config::clipboard_clear_secs` already exists), entry search/filter on the list,
a help overlay, a final zeroize audit, and usage docs. Decide there: clipboard
backend (e.g. `arboard`) and whether to ship idle auto-lock (§6) / token `/refresh`
UI in v1.
