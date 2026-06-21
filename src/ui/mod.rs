//! Rendering. `view` is a pure function of the [`App`] model: it picks a screen
//! renderer by [`Screen`] and draws into the frame. No state is mutated here.

mod components;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use crate::app::{App, EnrollField, EntryField, GroupField, Screen, StatusKind};
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
        Screen::Entries => render_entries(app, frame, body),
        Screen::Groups => render_groups(app, frame, body),
        Screen::EntryDetail => render_detail(app, frame, body),
        Screen::NewEntry => render_new_entry(app, frame, body),
        Screen::NewGroup => render_new_group(app, frame, body),
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

fn render_unlock(app: &App, frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::raw("Decrypt your local identity to start a session."),
        Line::raw(""),
        Line::from(format!("Passphrase: {}_", mask(&app.input))),
        Line::raw(""),
        Line::raw("Enter unlock · Esc quit").dim(),
    ];
    render_card(frame, area, "Unlock", lines, 9);
}

fn render_enroll(app: &App, frame: &mut Frame, area: Rect) {
    let pass_focused = app.enroll_field == EnrollField::Passphrase;
    let field = |label: &str, value: &str, focused: bool| {
        let marker = if focused { "› " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        let line = Line::from(format!("{marker}{label}{}{cursor}", mask(value)));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };
    let lines = vec![
        Line::raw("Create an encrypted identity for this device. The master passphrase"),
        Line::raw("encrypts your keys at rest and cannot be recovered if lost."),
        Line::raw(""),
        field("Passphrase: ", &app.input, pass_focused),
        field("Confirm:    ", &app.confirm, !pass_focused),
        Line::raw(""),
        Line::raw("Tab switch field · Enter enroll · Esc quit").dim(),
    ];
    render_card(frame, area, "Enroll", lines, 11);
}

fn render_awaiting(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Waiting for admin approval".bold()),
        Line::raw(""),
        Line::raw("This device is registered but not yet approved."),
        Line::raw("An administrator must approve it before you can continue."),
        Line::raw(""),
        Line::raw("Polling every few seconds · Esc quit").dim(),
    ];
    render_card(frame, area, "Awaiting approval", lines, 10);
}

fn render_resign(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Authorization failed".bold().fg(Color::Yellow)),
        Line::raw(""),
        Line::raw("The server rejected this device. Either an admin hasn't approved it"),
        Line::raw("yet, or your source IP changed since enrollment."),
        Line::raw(""),
        Line::from(vec![
            "[r]".bold(),
            " re-sign to bind to this IP (requires admin re-approval)".into(),
        ]),
        Line::from(vec!["[w]".bold(), " keep waiting for approval".into()]),
        Line::raw(""),
        Line::raw("Esc quit").dim(),
    ];
    render_card(frame, area, "Re-sign?", lines, 13);
}

fn render_entries(app: &App, frame: &mut Frame, area: Rect) {
    let [list_area, hint_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);

    let scope = if app.show_expired { "expired" } else { "valid" };
    let block = Block::bordered().title(format!(" Entries ({scope}) "));

    if app.entries.is_empty() {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(format!("No {scope} entries.").dim()),
        ])
        .block(block);
        frame.render_widget(msg, list_area);
    } else {
        let items: Vec<ListItem> = app
            .entries
            .iter()
            .map(|e| {
                let when = if app.show_expired {
                    "expired".to_string()
                } else {
                    format!("{}d left", e.expires)
                };
                ListItem::new(format!(
                    "{:<26} {:<34} {}",
                    truncate(&e.username, 26),
                    truncate(&e.url, 34),
                    when
                ))
            })
            .collect();
        let list = List::new(items)
            .block(block)
            .highlight_symbol("› ")
            .highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan));
        let mut state = ListState::default();
        state.select(Some(app.selected));
        frame.render_stateful_widget(list, list_area, &mut state);
    }

    frame.render_widget(
        Line::from(
            "↑/↓ move · Enter open · n new · t valid/expired · g groups · r refresh · Esc quit",
        )
        .dim(),
        hint_area,
    );
}

fn render_groups(app: &App, frame: &mut Frame, area: Rect) {
    let [list_area, hint_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let block = Block::bordered().title(" Groups ");

    if app.groups.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from("No groups.".dim())).block(block),
            list_area,
        );
    } else {
        let items: Vec<ListItem> = app
            .groups
            .iter()
            .map(|g| match &g.extra {
                Some(extra) if !extra.is_empty() => ListItem::new(format!(
                    "{:<28} {}",
                    truncate(&g.name, 28),
                    truncate(extra, 40)
                )),
                _ => ListItem::new(g.name.clone()),
            })
            .collect();
        frame.render_widget(List::new(items).block(block), list_area);
    }

    frame.render_widget(Line::from("n new · Esc back · q quit").dim(), hint_area);
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
        Line::raw(""),
        Line::from(if app.reveal {
            "s hide · e renew · Esc back · q quit"
        } else {
            "s reveal · e renew · Esc back · q quit"
        })
        .dim(),
    ];
    render_card(frame, area, "Entry", lines, 16);
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

    let row = |label: &str, value: String, field: EntryField| {
        let focused = form.field == field;
        let marker = if focused { "› " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        let line = Line::from(format!("{marker}{label:<11}{value}{cursor}"));
        if focused {
            line.fg(Color::Cyan)
        } else {
            line
        }
    };

    let title = if form.renewing {
        "Renew entry"
    } else {
        "New entry"
    };
    let lines = vec![
        row("Name", form.name.clone(), EntryField::Name),
        row("Group", group_label, EntryField::Group),
        Line::raw(""),
        row("Username", form.username.clone(), EntryField::Username),
        row("Password", password, EntryField::Password),
        row("URL", form.url.clone(), EntryField::Url),
        row("Notes", form.notes.clone(), EntryField::Notes),
        row("Valid days", form.valid_days.clone(), EntryField::ValidDays),
        Line::raw(""),
        Line::raw("Tab/↑↓ move · ←→ pick group · Ctrl+G generate · Enter save · Esc cancel").dim(),
    ];
    render_card(frame, area, title, lines, 16);
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
        Line::raw("Create a group to organize entries. Both fields are stored in plaintext"),
        Line::raw("on the server — don't put secrets here."),
        Line::raw(""),
        row("Name", &form.name, GroupField::Name),
        row("Extra", &form.extra, GroupField::Extra),
        Line::raw(""),
        Line::raw("Tab/↑↓ move · Enter save · Esc cancel").dim(),
    ];
    render_card(frame, area, "New group", lines, 12);
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
