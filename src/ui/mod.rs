//! Rendering. `view` is a pure function of the [`App`] model: it picks a screen
//! renderer by [`Screen`] and draws into the frame. No state is mutated here.

mod components;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Padding, Paragraph};
use ratatui::Frame;

use crate::app::{App, EnrollField, Screen, StatusKind};
use components::{centered, mask};

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
        Screen::Ready => render_ready(app, frame, body),
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

fn render_ready(app: &App, frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("✓ Session established".bold().fg(Color::Green)),
        Line::raw(""),
        Line::from(format!("Connected to {}", app.config.api_base_url)),
        Line::raw("This device is approved. Vault browsing arrives in M4."),
        Line::raw(""),
        Line::raw("q/Esc quit").dim(),
    ];
    render_card(frame, area, "Ready", lines, 9);
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
