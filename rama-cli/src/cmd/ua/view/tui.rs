//! Terminal interaction over an already loaded profile overview.

use super::display::Row;
use rama::{
    error::{BoxError, ErrorContext as _},
    utils::octets::kib,
};
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};

pub(super) fn run(rows: Vec<Row>, source: String) -> Result<(), BoxError> {
    App::new(rows, source).run()
}

struct App {
    rows: Vec<Row>,
    visible: Vec<usize>,
    selected: usize,
    filter: String,
    editing: bool,
    scroll: u16,
    source: String,
}

impl App {
    fn new(rows: Vec<Row>, source: String) -> Self {
        Self {
            visible: (0..rows.len()).collect(),
            rows,
            selected: 0,
            filter: String::new(),
            editing: false,
            scroll: 0,
            source,
        }
    }

    fn filter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                (row.label.to_lowercase().contains(&needle)
                    || row.details.to_lowercase().contains(&needle))
                .then_some(index)
            })
            .collect();
        self.selected = 0;
        self.scroll = 0;
    }

    fn key(&mut self, key: KeyEvent) -> bool {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return true;
        }
        if self.editing {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.editing = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.filter();
                }
                KeyCode::Char(ch) if !ch.is_control() && self.filter.len() < kib(1) => {
                    self.filter.push(ch);
                    self.filter();
                }
                _ => (),
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('/') => self.editing = true,
            KeyCode::Esc => {
                self.filter.clear();
                self.filter();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = self
                    .selected
                    .saturating_add(1)
                    .min(self.visible.len().saturating_sub(1));
                self.scroll = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                self.scroll = 0;
            }
            KeyCode::Home => {
                self.selected = 0;
                self.scroll = 0;
            }
            KeyCode::End => {
                self.selected = self.visible.len().saturating_sub(1);
                self.scroll = 0;
            }
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            _ => (),
        }
        false
    }

    fn draw(&self, frame: &mut Frame<'_>) {
        let [title, body, help] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .areas(frame.area());
        frame.render_widget(
            Paragraph::new(format!(
                "{} / {} profiles — {}\nFilter{}: {}",
                self.visible.len(),
                self.rows.len(),
                self.source,
                if self.editing { " (editing)" } else { "" },
                self.filter
            )),
            title,
        );
        let [list, details] = if body.width >= 90 {
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(body)
        } else {
            Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(body)
        };
        let mut state =
            ListState::default().with_selected((!self.visible.is_empty()).then_some(self.selected));
        frame.render_stateful_widget(
            List::new(
                self.visible
                    .iter()
                    .map(|index| ListItem::new(self.rows[*index].label.as_str())),
            )
            .block(Block::bordered().title("Profiles"))
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan)),
            list,
            &mut state,
        );
        let text = self
            .visible
            .get(self.selected)
            .map_or("No matching profiles.", |index| {
                self.rows[*index].details.as_str()
            });
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::bordered().title("Observed data"))
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            details,
        );
        frame.render_widget(Paragraph::new("↑↓ / j k select · / filter · Esc clear · PgUp/PgDn details\nq / Ctrl-C quit · protocols indicate observed data, not replay readiness"), help);
    }

    fn run(mut self) -> Result<(), BoxError> {
        let _guard = TerminalGuard;
        let mut terminal = ratatui::try_init().context("open profile viewer terminal")?;
        loop {
            terminal
                .draw(|frame| self.draw(frame))
                .context("draw profile viewer")?;
            match event::read().context("read profile viewer input")? {
                Event::Key(key) if key.kind == KeyEventKind::Press && self.key(key) => {
                    return Ok(());
                }
                _ => (),
            }
        }
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::ua::profile::model::{identity::ProfileKey, ua::UserAgentProfile};
    use ratatui::{Terminal, backend::TestBackend};
    #[test]
    fn viewer_filter_selection_and_resize_handle_empty_results() {
        let rows = ["alpha-library", "beta-library"]
            .map(|name| Row::from_profile(&UserAgentProfile::new(ProfileKey::new(name))).unwrap())
            .into_iter()
            .collect();
        let mut app = App::new(rows, "test input".to_owned());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(!app.key(key(KeyCode::Down)));
        assert_eq!(app.selected, 1);
        app.key(key(KeyCode::Char('/')));
        for ch in "beta".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        assert_eq!(app.visible, [1]);
        app.key(key(KeyCode::Enter));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("beta-library"));
        assert!(text.contains("Observed data"));
        app.filter = "no such profile".to_owned();
        app.filter();
        for code in [KeyCode::Down, KeyCode::Up, KeyCode::End, KeyCode::PageDown] {
            app.key(key(code));
        }
        assert!(app.visible.is_empty());
        for (width, height) in [(1, 1), (8, 3), (60, 12), (120, 24)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
        }
        app.key(key(KeyCode::Esc));
        assert_eq!(app.visible, [0, 1]);
        assert_eq!(app.scroll, 0);
        assert!(app.key(key(KeyCode::Char('q'))));
    }
}
