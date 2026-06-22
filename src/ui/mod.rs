//! Rendering. `view` is a pure function of the [`App`] model: it picks a screen
//! renderer by [`Screen`] and draws into the frame. No state is mutated here.

mod components;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Clear, HighlightSpacing, List, ListItem, Padding, Paragraph, Row, Table, TableState,
};
use ratatui::Frame;

use crate::app::{
    App, EnrollField, EntryField, GroupField, PwdGen, Screen, SignMode, StatusKind, PWD_GEN_PRESETS,
};
use components::{centered, mask, truncate};

/// Draw the whole UI for the current frame.
pub fn view(app: &App, frame: &mut Frame) {
    let [title, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(Line::from(" pwd-manager ".bold().reversed()), title);

    if app.show_help {
        render_help(frame, body);
    } else {
        match app.screen {
            Screen::Unlock => render_unlock(app, frame, body),
            Screen::Enroll => render_enroll(app, frame, body),
            Screen::Connecting => render_card(
                frame,
                body,
                "Connecting",
                vec![Line::raw("Verifying with the server…")],
                7,
            ),
            Screen::AwaitingApproval => render_awaiting(frame, body),
            Screen::ReSignPrompt => render_resign(frame, body),
            Screen::RefreshPrompt => render_refresh(app, frame, body),
            Screen::Entries => render_entries(app, frame, body),
            Screen::Groups => render_groups(app, frame, body),
            Screen::EntryDetail => render_detail(app, frame, body),
            Screen::NewEntry => render_new_entry(app, frame, body),
            Screen::NewGroup => render_new_group(app, frame, body),
        }
    }

    render_status(app, frame, status);
}

/// Render a bordered card of `lines` centred in `area`.
fn render_card(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>, height: u16) {
    let card = centered(area, 72, height);
    let block = Block::bordered()
        .title(format!(" {title} "))
        .padding(Padding::uniform(1));
    frame.render_widget(Paragraph::new(lines).block(block), card);
}

/// Shared layout for the interactive modal screens: a centred bordered box titled
/// `title`, a boxed "Keys" bar at the top (same style as the Entries screen), and
/// the `body` lines below with comfortable padding. Routing every screen through
/// this one helper is what makes the UI feel consistent.
fn render_modal(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    keys: &[(&str, &str)],
    body: Vec<Line>,
    width: u16,
    height: u16,
) {
    let modal = centered(area, width, height);
    let outer = Block::bordered().title(format!(" {title} "));
    let inner = outer.inner(modal);
    frame.render_widget(outer, modal);

    let [keys_area, body_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(inner);

    frame.render_widget(
        Paragraph::new(shortcut_bar(keys)).block(Block::bordered().title(" Keys ")),
        keys_area,
    );
    frame.render_widget(
        Paragraph::new(body).block(Block::default().padding(Padding::new(2, 2, 1, 0))),
        body_area,
    );
}

fn render_unlock(app: &App, frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::raw("Decrypt your local identity to start a session."),
        Line::raw(""),
        Line::from(format!("Passphrase: {}_", mask(&app.input))),
    ];
    render_modal(
        frame,
        area,
        "Unlock",
        &[("↵", "unlock"), ("Esc", "quit")],
        lines,
        72,
        11,
    );
}

fn render_enroll(app: &App, frame: &mut Frame, area: Rect) {
    // `masked` hides the value (ehlo/passphrase); the account name shows in clear.
    let field = |label: &str, value: &str, focused: bool, masked: bool| {
        let marker = if focused { "› " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        let shown = if masked {
            mask(value)
        } else {
            value.to_string()
        };
        let line = Line::from(format!("{marker}{label}{shown}{cursor}"));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };
    let mode = match app.sign_mode {
        SignMode::SignUp => "Create account",
        SignMode::SignIn => "Sign in",
    };
    let lines = vec![
        Line::from(vec!["Mode: ".into(), mode.bold()]),
        Line::raw("Name + ehlo are your account credentials; the master passphrase"),
        Line::raw("encrypts your keys at rest and cannot be recovered if lost."),
        Line::raw(""),
        field(
            "Name:       ",
            &app.account_name,
            app.enroll_field == EnrollField::Name,
            false,
        ),
        field(
            "Ehlo:       ",
            &app.ehlo,
            app.enroll_field == EnrollField::Ehlo,
            true,
        ),
        field(
            "Passphrase: ",
            &app.input,
            app.enroll_field == EnrollField::Passphrase,
            true,
        ),
        field(
            "Confirm:    ",
            &app.confirm,
            app.enroll_field == EnrollField::Confirm,
            true,
        ),
    ];
    render_modal(
        frame,
        area,
        "Enroll",
        &[
            ("Tab", "next"),
            ("Ctrl+T", "create/sign-in"),
            ("↵", "submit"),
            ("Esc", "quit"),
        ],
        lines,
        78,
        16,
    );
}

fn render_awaiting(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Waiting for admin approval".bold()),
        Line::raw(""),
        Line::raw("This device is enrolled but not yet approved."),
        Line::raw("An administrator must approve it before you can continue."),
        Line::raw(""),
        Line::raw("Polling every few seconds…").dim(),
    ];
    render_modal(
        frame,
        area,
        "Awaiting approval",
        &[("Esc", "quit")],
        lines,
        72,
        12,
    );
}

fn render_resign(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Authorization failed".bold().fg(Color::Yellow)),
        Line::raw(""),
        Line::raw("The server rejected this device. Either an admin hasn't approved it"),
        Line::raw("yet, or your source IP changed since enrollment."),
        Line::raw(""),
        Line::raw("Re-signing re-binds your identity to this IP, but then an admin"),
        Line::raw("must approve the device again before it works."),
    ];
    render_modal(
        frame,
        area,
        "Re-sign?",
        &[
            ("r", "re-sign to this IP"),
            ("w", "keep waiting"),
            ("Esc", "quit"),
        ],
        lines,
        76,
        13,
    );
}

/// Relative column widths for the entries table. `Fill` makes each column grow to
/// share the full table width (like CSS `flex-grow`), so the row spreads across the
/// pane instead of bunching on the left.
const ENTRY_WIDTHS: [Constraint; 7] = [
    Constraint::Fill(3), // USERNAME
    Constraint::Fill(3), // URL
    Constraint::Fill(2), // PWD
    Constraint::Fill(1), // VALID
    Constraint::Fill(2), // CREATED
    Constraint::Fill(2), // UPDATED
    Constraint::Fill(2), // EXPIRES
];

fn render_entries(app: &App, frame: &mut Frame, area: Rect) {
    let [keys_area, list_area, hint_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    // Keyboard shortcuts, boxed at the top: bold keys, ` │ ` separators.
    let keys = shortcut_bar(&[
        ("↑/↓", "move"),
        ("↵", "open"),
        ("n", "new"),
        ("/", "search"),
        ("t", "valid/expired"),
        ("g", "groups"),
        ("r", "refresh"),
        ("?", "help"),
        ("q", "quit"),
    ]);
    frame.render_widget(
        Paragraph::new(keys).block(Block::bordered().title(" Keys ")),
        keys_area,
    );

    let scope = if app.show_expired { "expired" } else { "valid" };
    let visible = app.visible_indices();
    let title = if app.search.is_empty() {
        format!(" Entries ({scope}) ")
    } else {
        format!(" Entries ({scope}) · /{} ", app.search)
    };
    let block = Block::bordered().title(title);

    if visible.is_empty() {
        let note = if app.search.is_empty() {
            format!("No {scope} entries.")
        } else {
            format!("No matches for “{}”.", app.search)
        };
        let msg = Paragraph::new(vec![Line::raw(""), Line::from(note.dim())]).block(block);
        frame.render_widget(msg, list_area);
    } else {
        let header = Row::new([
            "USERNAME", "URL", "PWD", "VALID", "CREATED", "UPDATED", "EXPIRES",
        ])
        .style(Style::new().add_modifier(Modifier::BOLD | Modifier::DIM));

        let rows: Vec<Row> = visible
            .iter()
            .map(|&i| {
                let e = &app.entries[i];
                let when = if app.show_expired {
                    "expired".to_string()
                } else {
                    format!("{}d left", e.expires)
                };
                Row::new([
                    e.username.clone(),
                    e.url.clone(),
                    e.pwd_preview.clone(),
                    format!("{}d", e.valid_since_days),
                    date_only(&e.created_at),
                    date_only(&e.updated_at),
                    when,
                ])
            })
            .collect();

        // `Table` spreads the columns across the full width via the `Fill` weights
        // and draws its own header + border, keeping the headings aligned with rows.
        let table = Table::new(rows, ENTRY_WIDTHS)
            .header(header)
            .block(block)
            .row_highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan))
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always);
        let mut state = TableState::default();
        state.select(Some(app.selected));
        frame.render_stateful_widget(table, list_area, &mut state);
    }

    // The bottom line is only used to capture the search query now that the
    // shortcuts live in their own box at the top.
    if app.searching {
        frame.render_widget(
            Line::from(format!("Search: {}_", app.search)).fg(Color::Cyan),
            hint_area,
        );
    }
}

/// Build a one-line shortcut bar: bold cyan keys, plain labels, dim ` │ ` dividers.
fn shortcut_bar(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::with_capacity(pairs.len() * 3);
    for (i, (key, label)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::from(" │ ").dim());
        }
        spans.push(Span::from(key.to_string()).bold().fg(Color::Cyan));
        spans.push(Span::from(format!(" {label}")));
    }
    Line::from(spans)
}

/// Keep just the date portion of a backend timestamp (`2026-06-22 00:08:57` →
/// `2026-06-22`); blanks render as a dash.
fn date_only(ts: &str) -> String {
    if ts.is_empty() {
        return "—".to_string();
    }
    ts.chars().take(10).collect()
}

fn render_groups(app: &App, frame: &mut Frame, area: Rect) {
    let [keys_area, list_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);

    frame.render_widget(
        Paragraph::new(shortcut_bar(&[
            ("n", "new"),
            ("?", "help"),
            ("Esc", "entries"),
            ("q", "quit"),
        ]))
        .block(Block::bordered().title(" Keys ")),
        keys_area,
    );

    let block = Block::bordered().title(format!(" Groups ({}) ", app.groups.len()));

    if app.groups.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![Line::raw(""), Line::from("No groups.".dim())]).block(block),
            list_area,
        );
    } else {
        let items: Vec<ListItem> = app
            .groups
            .iter()
            .map(|g| match &g.extra {
                Some(extra) if !extra.is_empty() => ListItem::new(Line::from(vec![
                    format!("  {:<28}", truncate(&g.name, 28)).into(),
                    truncate(extra, 40).dim(),
                ])),
                _ => ListItem::new(format!("  {}", g.name)),
            })
            .collect();
        frame.render_widget(List::new(items).block(block), list_area);
    }
}

fn render_detail(app: &App, frame: &mut Frame, area: Rect) {
    let Some(detail) = &app.detail else {
        render_card(frame, area, "Entry", vec![Line::raw("No entry.")], 5);
        return;
    };
    let s = &detail.secret;
    let password = if app.reveal {
        s.password.clone()
    } else {
        mask(&s.password)
    };
    let field = |label: &str, value: &str| {
        Line::from(vec![
            format!("{label:<10}").bold(),
            value.to_string().into(),
        ])
    };
    let none = "(none)".to_string();
    let lines = vec![
        field("Name", detail.name.as_ref().unwrap_or(&none)),
        field("Group", detail.group.as_ref().unwrap_or(&none)),
        Line::raw(""),
        field("Username", &s.username),
        field("Password", &password),
        field("URL", &s.url),
        field("Notes", &s.notes),
        Line::raw(""),
        field(
            "Expires",
            &format!(
                "{} day(s) · valid window {} day(s)",
                detail.expires, detail.valid_since_days
            ),
        ),
        field("Created", &detail.created_at),
        field("Updated", &detail.updated_at),
    ];
    let toggle = if app.reveal {
        ("s", "hide")
    } else {
        ("s", "reveal")
    };
    render_modal(
        frame,
        area,
        "Entry",
        &[
            toggle,
            ("c", "copy pwd"),
            ("u", "copy user"),
            ("e", "edit"),
            ("Esc", "back"),
            ("?", "help"),
        ],
        lines,
        76,
        19,
    );
}

fn render_refresh(app: &App, frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Rotate device token".bold()),
        Line::raw(""),
        Line::raw("Requests a fresh device token from the server (keeps approval, but"),
        Line::raw("must be at your registered IP). The new token is saved to your local"),
        Line::raw("store, so confirm with your master passphrase."),
        Line::raw(""),
        Line::from(format!("Passphrase: {}_", mask(&app.input))),
    ];
    render_modal(
        frame,
        area,
        "Refresh token",
        &[("↵", "confirm"), ("Esc", "cancel")],
        lines,
        78,
        14,
    );
}

fn render_help(frame: &mut Frame, area: Rect) {
    let key = |k: &str, desc: &str| {
        Line::from(vec![format!("  {k:<10}").bold(), desc.to_string().into()])
    };
    let lines = vec![
        Line::from("Entries".bold().fg(Color::Cyan)),
        key("↑/↓", "move · Enter opens the selected entry"),
        key("/", "search (filters by username/URL) · Esc clears"),
        key("n", "new entry · t toggle valid/expired · r refresh list"),
        key("g", "groups · Ctrl+R rotate device token · q quit"),
        Line::raw(""),
        Line::from("Entry detail".bold().fg(Color::Cyan)),
        key(
            "s",
            "reveal/hide password · c copy password · u copy username",
        ),
        key("e", "edit (updates in place) · Esc back"),
        Line::raw(""),
        Line::from("Groups".bold().fg(Color::Cyan)),
        key("n", "new group · Esc back"),
        Line::raw(""),
        Line::raw("Copied secrets auto-clear from the clipboard; the vault locks").dim(),
        Line::raw("automatically after it sits idle.").dim(),
        Line::raw(""),
        Line::raw("Press any key to close.").dim(),
    ];
    render_card(frame, area, "Help", lines, 20);
}

fn render_new_entry(app: &App, frame: &mut Frame, area: Rect) {
    let Some(form) = &app.entry_form else {
        render_card(frame, area, "New entry", vec![Line::raw("No form.")], 5);
        return;
    };
    let group_label = match app.groups.get(form.group_idx) {
        Some(g) => format!(
            "‹ {} ›  ({}/{})",
            g.name,
            form.group_idx + 1,
            app.groups.len()
        ),
        None => "‹ none ›".to_string(),
    };
    // The password reveals only while its own field is focused (authoring feedback).
    let password = if form.field == EntryField::Password {
        form.password.clone()
    } else {
        mask(&form.password)
    };

    let title = if form.edit_uuid.is_some() {
        "Edit entry"
    } else {
        "New entry"
    };

    let row = |label: &str, value: String, field: EntryField| {
        let focused = form.field == field;
        let marker = if focused { "› " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        let line = Line::from(format!("{marker}{label:<12}{value}{cursor}"));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };

    let lines = vec![
        row("Name", form.name.clone(), EntryField::Name),
        row("Group", group_label, EntryField::Group),
        Line::raw(""),
        row("Username", form.username.clone(), EntryField::Username),
        row("Password", password, EntryField::Password),
        row("URL", form.url.clone(), EntryField::Url),
        row("Notes", form.notes.clone(), EntryField::Notes),
        Line::raw(""),
        row("Valid days", form.valid_days.clone(), EntryField::ValidDays),
    ];
    render_modal(
        frame,
        area,
        title,
        &[
            ("Tab/↑↓", "move"),
            ("←→", "pick group"),
            ("Ctrl+G", "generate"),
            ("↵", "save"),
            ("Esc", "cancel"),
        ],
        lines,
        84,
        20,
    );

    // The Ctrl+G length picker, when open, floats on top of the form.
    if app.pwd_gen.is_some() {
        render_pwd_gen(app, frame, area);
    }
}

/// The Ctrl+G password-length picker: a small modal floating over the entry form,
/// offering the preset lengths plus a "Custom" row that captures a typed number.
fn render_pwd_gen(app: &App, frame: &mut Frame, area: Rect) {
    let Some(gen) = &app.pwd_gen else {
        return;
    };
    // A selectable row: cyan with a `›` marker when the cursor is on it.
    let row = |label: String, focused: bool| {
        let marker = if focused { "› " } else { "  " };
        let line = Line::from(format!("{marker}{label}"));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };

    let mut lines = vec![
        Line::raw("How many characters? Pick one or type your own.").dim(),
        Line::raw(""),
    ];
    for (i, len) in PWD_GEN_PRESETS.iter().enumerate() {
        lines.push(row(format!("{len} characters"), gen.idx == i));
    }
    let custom_focused = gen.idx == PwdGen::CUSTOM_IDX;
    let cursor = if custom_focused { "_" } else { "" };
    let custom_label = if gen.custom.is_empty() {
        format!("Custom: (type a number){cursor}")
    } else {
        format!("Custom: {} characters{cursor}", gen.custom)
    };
    lines.push(row(custom_label, custom_focused));

    // Clear the cells under the popup first so the form doesn't bleed through the
    // gaps; `centered` is deterministic, so render_modal lands on the same rect.
    let modal = centered(area, 54, 14);
    frame.render_widget(Clear, modal);
    render_modal(
        frame,
        area,
        "Generate password",
        &[
            ("↑/↓", "move"),
            ("0-9", "custom"),
            ("↵", "generate"),
            ("Esc", "cancel"),
        ],
        lines,
        54,
        14,
    );
}

fn render_new_group(app: &App, frame: &mut Frame, area: Rect) {
    let Some(form) = &app.group_form else {
        render_card(frame, area, "New group", vec![Line::raw("No form.")], 5);
        return;
    };
    let row = |label: &str, value: &str, field: GroupField| {
        let focused = form.field == field;
        let marker = if focused { "› " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        let line = Line::from(format!("{marker}{label:<7}{value}{cursor}"));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };
    let lines = vec![
        Line::raw("Create a group to organize entries. Both fields are stored in").dim(),
        Line::raw("plaintext on the server — don't put secrets here.").dim(),
        Line::raw(""),
        row("Name", &form.name, GroupField::Name),
        row("Extra", &form.extra, GroupField::Extra),
    ];
    render_modal(
        frame,
        area,
        "New group",
        &[("Tab/↑↓", "move"), ("↵", "save"), ("Esc", "cancel")],
        lines,
        78,
        13,
    );
}

fn render_status(app: &App, frame: &mut Frame, area: Rect) {
    let color = match app.status.kind {
        StatusKind::Info => Color::Gray,
        StatusKind::Success => Color::Green,
        StatusKind::Warning => Color::Yellow,
        StatusKind::Error => Color::Red,
    };
    let text = format!(" {}", app.status.text);
    frame.render_widget(Line::from(text).fg(color), area);
}
