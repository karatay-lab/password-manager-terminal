use color_eyre::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Padding, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::config::Config;

/// Top-level application state.
///
/// M0 is intentionally minimal: render one frame and quit. Screens (Sign-in,
/// Vault, Entry) and the message/update loop arrive in later milestones.
pub struct App {
    config: Config,
    running: bool,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            running: false,
        }
    }

    /// Draw/event loop: redraw, then block for input, until the user quits.
    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        self.running = true;
        while self.running {
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let [title, body, status] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        frame.render_widget(Line::from(" pwd-manager ".bold().reversed()), title);

        let block = Block::bordered()
            .title(" pwd-manager-terminal ")
            .padding(Padding::uniform(1));
        let lines = vec![
            "Scaffold ready (M0).".bold().into(),
            Line::raw(""),
            Line::raw(format!("Backend: {}", self.config.api_base_url)),
            Line::raw(format!("Store:   {}", self.config.data_dir)),
            Line::raw(""),
            "Screens to come: Sign-in · Vault · Entry.".dim().into(),
        ];
        frame.render_widget(Paragraph::new(lines).block(block), body);

        frame.render_widget(Line::from(" q/Esc quit ".dim()).centered(), status);
    }

    fn handle_events(&mut self) -> Result<()> {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                self.on_key(key);
            }
        }
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) {
        match (key.modifiers, key.code) {
            (_, KeyCode::Char('q') | KeyCode::Esc) => self.running = false,
            (KeyModifiers::CONTROL, KeyCode::Char('c')) => self.running = false,
            _ => {}
        }
    }
}
