//! Small rendering helpers shared across screens.

use ratatui::layout::{Constraint, Flex, Layout, Rect};

/// Carve a fixed-size box centred within `area` (clamped to the area's bounds).
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let [col] = Layout::horizontal([Constraint::Length(w)])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::vertical([Constraint::Length(h)])
        .flex(Flex::Center)
        .areas(col);
    cell
}

/// Render a secret as bullets — one per character — so it's never shown on screen.
pub fn mask(secret: &str) -> String {
    "•".repeat(secret.chars().count())
}
