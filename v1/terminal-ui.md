# Terminal UI spec — pwd-manager-terminal

The full screen-by-screen UI design for the ratatui client. Pairs with
[`plan.md`](./plan.md) (architecture) and [`../docs/protocol-notes.md`](../docs/protocol-notes.md)
(verified API). Three primary screens:

1. **Sign-in** — local identity check + `/greet` `/register` `/re-sign` `/refresh`.
2. **Vault** — search bar (filter by group/name) + paginated password list.
3. **Entry** — opened on `Space`; view/edit password, group, extra; create new.

---

## 0. Global conventions

- **Frame:** every screen is one `Block` with a title (`pwd-manager · <Screen>`),
  a body, and a one-line **status/hint bar** at the bottom. A connection dot
  (`● host` reachable / `○ host` down) sits in the title bar.
- **Focus:** the focused widget gets a highlighted border; the selected list row
  uses a `❯` marker + reversed style.
- **Modals:** errors, confirmations and the copy toast render over a `Clear`ed
  centered `Rect` (z-order by draw order).
- **Colors:** expiry uses green (>14d) / yellow (≤14d) / red (expired). Errors red,
  success green, hints dim.
- **Secrets:** passwords render masked (`••••`) until toggled; copied secrets show a
  countdown toast and auto-clear from the clipboard (`PWM_CLIPBOARD_CLEAR_SECS`).
- **Global keys:** `q` quit · `?` help overlay · `Esc` back/cancel · `Ctrl-L` lock.

### Navigation map

```
            ┌─────────────┐  verify 200   ┌─────────────┐  Space   ┌─────────────┐
  start ───▶│  Sign-in    │ ────────────▶ │   Vault     │ ───────▶ │   Entry     │
            │  (Screen 1) │ ◀──────────── │  (Screen 2) │ ◀─Esc──── │ (Screen 3)  │
            └─────────────┘   Ctrl-L lock └─────────────┘   n new ─▶│ (create)    │
                                                                     └─────────────┘
```

---

## 1. Screen 1 — Sign-in / Auth

On launch the app inspects `~/.pwd-manager/` (override: `PWM_DATA_DIR`) for the
encrypted local store: X25519 **keypair**, **server public key**, **device-token**,
**ehlo secret**. The screen is a small state machine driven by what it finds and by
the server's response.

### State A — first run (no identity)

```
┌ pwd-manager · Sign in ───────────────────────────────── ● localhost:53971 ┐
│                                                                            │
│   No local identity in ~/.pwd-manager                                      │
│                                                                            │
│   This device isn't enrolled yet. Enrolling will:                          │
│     1. generate an X25519 keypair                                          │
│     2. POST /greet  — exchange public keys, derive the shared key          │
│     3. POST /register — seal a device token + ehlo (awaits admin approval) │
│                                                                            │
│              ┌────────────────────────┐                                    │
│              │   Enroll this device   │                                    │
│              └────────────────────────┘                                    │
│                                                                            │
├────────────────────────────────────────────────────────────────────────────┤
│ Enter enroll · e edit server URL · q quit                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

`Enter` → runs greet + register (token/ehlo generated and persisted to the encrypted
store), then transitions to **State B**.

### State B — awaiting admin approval

```
│   ⠋  Registered — waiting for admin approval                                │
│      identity created at 10.0.0.5                                           │
│      Polling GET /verify every 5s … (admin must approve this device)        │
│                                                                            │
│ r retry now · q quit                                                       │
```

Auto-polls `/verify` on a debounced timer (respect the 10 rps limit; 5s is plenty).
On `200` → go to Vault.

### State C — identity found (verify / recovery)

```
┌ pwd-manager · Sign in ───────────────────────────────── ● localhost:53971 ┐
│   Local identity found in ~/.pwd-manager                                    │
│     keys          ✓ x25519 keypair + server public key                     │
│     device-token  ✓ present                                                 │
│                                                                            │
│   Verifying session …   ✗ 401 unauthorized                                 │
│                                                                            │
│   The server rejected this device. Likely one of:                          │
│     • not approved yet     • your IP changed     • token rotated elsewhere  │
│                                                                            │
│     ┌──────────┐   ┌──────────┐   ┌──────────┐                             │
│     │ Re-sign  │   │ Refresh  │   │  Retry   │                             │
│     └──────────┘   └──────────┘   └──────────┘                             │
│      IP changed     rotate token   re-verify                               │
├────────────────────────────────────────────────────────────────────────────┤
│ ←/→ select · Enter run · q quit                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

- **Verify** runs automatically on load. `200` → straight to Vault (this panel only
  appears on failure).
- **Re-sign** → `POST /re-sign` (token sent as **plain hex**, ehlo sealed); updates the
  server to the new IP but **resets approval** → returns to State B.
- **Refresh** → `POST /refresh` (token + ehlo sealed); stores the returned new token;
  retries verify.
- **Retry** → re-run `/verify`.

> If the store is passphrase-encrypted (see plan §6, ❓DECIDE), an **Unlock** prompt
> (masked input) precedes State C.

### Screen 1 keys

| Key | Action |
|-----|--------|
| `Enter` | run focused action (Enroll / Unlock / selected recovery button) |
| `←` `→` | move between recovery buttons (State C) |
| `e` | edit server URL (overrides `PWM_API_BASE_URL` for this run) |
| `r` | retry verify / poll now |
| `q` | quit |

### API mapping

| UI action | Call | Notes |
|-----------|------|-------|
| Enroll | `POST /greet` → `POST /register` | generate+persist keypair, token, ehlo |
| (poll) | `GET /verify` | 200 ⇒ approved |
| Re-sign | `POST /re-sign` | resets `is_confirmed` ⇒ needs re-approval |
| Refresh | `POST /refresh` | returns + stores new device token |

---

## 2. Screen 2 — Vault (search + list + pagination)

```
┌ pwd-manager · Vault ──────────────────────────────────── ● 10.0.0.5 ┐
│ Search  goo▏                                        [ + New  (n) ]   │
│ ┌──────────────────────────────────────────────────────────────────┐│
│ │ Name             Group       Username          Expires            ││
│ │ ────────────────────────────────────────────────────────────     ││
│ │❯ Google          Google      me@gmail.com      in 21 days         ││
│ │  Google Cloud    Google      ops@acme.io       in 3 days   ⚠      ││
│ │  Gmail (work)    Google      berkay@acme.io    expired     ✗      ││
│ │  Sign-in SSO     Sign        berkay            in 88 days         ││
│ │                                                                  ▓ ││
│ │                                                                  ░ ││
│ └──────────────────────────────────────────────────────────────────┘│
│                                              Valid ▸  |  Expired      │
├────────────────────────────────────────────────────────────────────────┤
│ Page 1/3 · 12/47 loaded  ·  ↑↓ move  Space open  / search  ⇆ list  n │
└────────────────────────────────────────────────────────────────────────┘
```

### Components (ratatui)

- **Search bar** — a single-line input (`Paragraph` + cursor). Case-insensitive
  substring filter over **group name and entry name** (`goo` → Google entries).
  `/` focuses it; `Esc` clears+unfocuses.
- **List** — `Table` + `TableState` (selectable rows) with a `Scrollbar`. Columns:
  Name · Group · Username · Expires. Expiry is color-coded; `⚠` ≤14d, `✗` expired.
- **Valid / Expired tab** — `Tabs` (or a toggle). Valid = `/pwd/list/valid`,
  Expired = `/pwd/list/expired`. `⇆`/`Tab` switches.
- **New button** — top-right; `n` opens the editor in **create mode** (Screen 3).
- **Status bar** — pagination + key hints.

### ⚠️ Data hydration (important backend constraint)

`/pwd/list/valid|expired` returns only `{uuid, pwd(sealed), expires, created_at,
valid_since_days}` — **no name, no group**. Name/group/username come only from
`/pwd/get/{uuid}`. Therefore:

1. Load entries page-by-page (`take`/`size`, size 1–200) to get uuids + expiry.
2. **Hydrate** each entry via `GET /pwd/get/{uuid}` to obtain `name`, `group.name`,
   and (after `open(pwd)`) the username — needed to render and search. Throttle to
   the 10 rps limit; show a subtle "loading…" state per unhydrated row.
3. Cache hydrated metadata in memory (zeroized on lock). Search/filter and paginate
   over the cache.

> **❓DECIDE — pagination model.** The API returns no total count. Options:
> **(a)** load+hydrate everything up front, then paginate/search purely client-side
> (simplest; fine for modest vaults); **(b)** lazy server pages with on-demand
> hydration (scales, but search only covers loaded pages). Recommend (a) for v1.

### Screen 2 keys

| Key | Action |
|-----|--------|
| `↑` `↓` / `j` `k` | move selection |
| `PgUp` `PgDn` | page the list |
| `Space` | open selected entry (Screen 3) |
| `/` | focus search · `Esc` clear |
| `Tab` / `⇆` | toggle Valid ⇄ Expired |
| `n` | new password (Screen 3, create mode) |
| `c` / `u` | quick-copy password / username of selection |
| `r` | refresh list from server |
| `Ctrl-L` | lock · `q` quit |

---

## 3. Screen 3 — Entry (detail / edit / create)

Opened on `Space` (edit existing) or `n` (create new). Same form, two modes.

### Edit mode

```
┌ pwd-manager · Entry ───────────────────────────────────────────────┐
│  Name      │ Google                                        │        │
│  Group     │ Google                                    ▾   │        │
│  Username  │ me@gmail.com                                  │        │
│  Password  │ ••••••••••••••              │  s show   c copy │        │
│  URL       │ https://accounts.google.com                   │        │
│  Notes     │ recovery email set; 2FA enabled               │        │
│                                                                     │
│  Expires   in 21 days   (created 2026-05-30 · valid 30 days)        │
│            ⓘ Saving does NOT renew expiry. Use Duplicate to renew.  │
│                                                                     │
│     ┌────────┐   ┌──────────────┐   ┌────────┐                      │
│     │  Save  │   │ Duplicate ⟳  │   │ Cancel │                      │
│     └────────┘   └──────────────┘   └────────┘                      │
├───────────────────────────────────────────────────────────────────────┤
│ Tab/↑↓ field · Enter edit field · Ctrl-S save · Esc back            │
└───────────────────────────────────────────────────────────────────────┘
```

### Create mode (`n`)

Same layout, empty fields, titled **New entry**, plus a **Valid for [ 30 ] days**
field (clamped 1–365). `Save` → `POST /pwd/create`.

### Fields → API mapping

| UI field | Stored as | Sealed? |
|----------|-----------|---------|
| Name | `name` | plaintext (server, ≤256) |
| Group | `group_id` (picker from `/group/list`) | — |
| Password | inside sealed `pwd` JSON | **sealed** |
| Username, URL | inside sealed `pwd` JSON *(recommended)* | **sealed** (❓DECIDE) |
| Notes / extra | `extra` JSON `{"note":…}` | plaintext (server, ≤4096) |
| Valid for (create only) | `valid_since_days` | — (clamped 1–365) |

> Sealed `pwd` plaintext is **client-defined** JSON, e.g.
> `{"password":"…","username":"…","url":"…"}`. **Anything in `name`/`extra` is stored
> in plaintext on the server** — keep secrets inside `pwd`.
> **❓DECIDE:** put username/url in sealed `pwd` (private) or plaintext `extra`
> (searchable without decrypting). Recommend sealed for privacy; we still decrypt on
> hydration for search.

### Actions

- **Save** — edit → `PUT /pwd/update/{uuid}` (re-seal `pwd`, send `group_id`, `name`,
  `extra`); create → `POST /pwd/create`.
- **Duplicate ⟳** — because `update` never resets `created_at`/`valid_since_days`,
  "renewing" an aging entry = `POST /pwd/create` with the same contents + fresh
  `valid_since_days`. The old entry remains (no delete endpoint) and ages out.
- **Copy / Show** — `c` copies password (auto-clear toast), `s` toggles reveal.
- **Cancel / Esc** — discard, back to Vault (confirm if there are unsaved edits).

### Screen 3 keys

| Key | Action |
|-----|--------|
| `Tab` / `↑` `↓` | next / previous field |
| `Enter` | edit focused field / open group picker |
| `s` | show/hide password |
| `c` / `u` | copy password / username |
| `Ctrl-S` | save |
| `Esc` | cancel (confirm if dirty) |

---

## 4. Cross-cutting states

- **Loading:** spinner in the title bar during any network call; list rows show a
  per-row placeholder until hydrated.
- **Empty vault:** centered hint "No passwords yet — press `n` to create one."
- **Errors:** modal over `Clear`; map the generic `401 "unauthorized"` to "Session
  rejected — your IP may have changed or approval was revoked. Re-sign?" with a jump
  back to Screen 1. Show rate-limit (`429`/governor) as "Slow down — retrying…".
- **Copy toast:** `Copied password · clears in 27s` countdown, bottom-right.
- **Lock (`Ctrl-L`):** zeroize decrypted secrets + hydrated cache, return to Screen 1
  (Unlock/Verify).

## 5. ratatui widget cheat-sheet

| UI element | Widget |
|------------|--------|
| Screen frame + titles | `Block` |
| Search / text fields | `Paragraph` + manual cursor |
| Password list | `Table` + `TableState` + `Scrollbar` |
| Valid/Expired switch | `Tabs` |
| Buttons | styled `Paragraph`/`Span` (focus = reversed) |
| Modals / toasts | `Clear` + `Block` over a centered `Rect` |
| Spinner | throbber char cycled on tick |

## 6. Open UI decisions

- [ ] Pagination model — load-all+client-side vs lazy server pages (§2).
- [ ] Username/URL — sealed in `pwd` vs plaintext `extra` (§3).
- [ ] Group picker UX — dropdown popup vs cycle; inline "create group"?
- [ ] Keymap — vim (`hjkl`) vs arrows (mirror plan §8).
- [ ] Store unlock — passphrase prompt vs OS keyring (mirror plan §6).
