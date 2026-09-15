//! Terminal viewer for a [`View`] over a decoded capture.
//!
//! The viewer knows nothing about HAR or qlog: it renders a timeline, a list of
//! entries and the selected entry's sections, whatever produced them. Keeping
//! [`AppState`] free of a terminal handle keeps selection, filtering and
//! rendering unit-testable with ratatui's `TestBackend`.

use std::{io::Write as _, time::Duration};

use rama::{
    error::{BoxError, ErrorContext as _},
    inspect::timeline::{Entry, Level, Section, SectionBody, View},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    prelude::*,
    widgets::{
        Block, Borders, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap,
    },
};

use tokio::sync::mpsc;

use super::util;

/// Open the viewer and run it until the user quits.
pub(super) async fn run(view: View) -> Result<(), BoxError> {
    let terminal = ratatui::init();
    let _guard = TerminalGuard;
    App {
        terminal,
        state: AppState::new(view),
    }
    .event_loop()
    .await
}

/// Restores the terminal out of raw mode / the alternate screen on drop, even
/// if the event loop returns early or panics.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

struct App {
    terminal: DefaultTerminal,
    state: AppState,
}

impl App {
    async fn event_loop(&mut self) -> Result<(), BoxError> {
        let mut events = spawn_input_reader()?;
        let mut needs_redraw = true;
        loop {
            if needs_redraw {
                let state = &mut self.state;
                self.terminal
                    .draw(|frame| state.render(frame))
                    .context("draw capture viewer")?;
                needs_redraw = false;
            }

            // Park until the reader thread has something. An idle viewer then
            // costs no wakeups at all, where polling on a tick costs them for
            // as long as the capture stays open.
            let Some(event) = events.recv().await else {
                return Ok(());
            };
            // Drain whatever queued up behind it before drawing again, so a
            // held key or a resize storm redraws once instead of once per event.
            let mut next = Some(event);
            while let Some(event) = next.take() {
                match event.context("read terminal event")? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        match self.state.on_key(key) {
                            Action::Quit => return Ok(()),
                            Action::Copy => {
                                self.copy_selected()?;
                                needs_redraw = true;
                            }
                            Action::Redraw => needs_redraw = true,
                            Action::None => {}
                        }
                    }
                    Event::Resize(_, _) => needs_redraw = true,
                    _ => {}
                }
                next = events.try_recv().ok();
            }
        }
    }

    /// Copy through OSC 52, the one clipboard channel a terminal offers without
    /// a platform integration; it also crosses ssh and multiplexers.
    ///
    /// The sequence is fire-and-forget: no terminal acknowledges it, and a
    /// terminal that does not implement it (the legacy Windows console) or
    /// that refuses it by default (tmux without `set-clipboard on`, xterm
    /// without `allowWindowOps`) is indistinguishable from one that copied.
    /// So the status says what was actually done rather than claiming a
    /// clipboard the viewer cannot observe.
    fn copy_selected(&mut self) -> Result<(), BoxError> {
        let Some(item) = self
            .state
            .view
            .selected()
            .and_then(|entry| entry.copy.first().cloned())
        else {
            self.state.status = Some("nothing to copy for this entry".to_owned());
            return Ok(());
        };
        match item.text() {
            Ok(text) => {
                let mut out = std::io::stdout();
                write!(out, "\x1b]52;c;{}\x07", BASE64.encode(text.as_bytes()))
                    .context("write clipboard escape")?;
                out.flush().context("flush clipboard escape")?;
                self.state.status = Some(format!("sent {} to the clipboard (OSC 52)", item.label));
            }
            Err(error) => self.state.status = Some(format!("cannot copy {}: {error}", item.label)),
        }
        Ok(())
    }
}

/// How long the reader thread parks on the console before re-checking whether
/// the viewer has quit.
const INPUT_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Read terminal events on a dedicated thread and hand them to the event loop.
///
/// `crossterm`'s reader is blocking, which leaves two options: block a runtime
/// worker on console input, or tick. Ticking is what the viewer used to do, and
/// it costs a wakeup 60 times a second for as long as a capture stays open --
/// on a laptop that is the difference between an idle process and one that
/// keeps the CPU out of its low-power states. A thread parks on the console
/// handle instead, so an idle viewer is genuinely idle.
fn spawn_input_reader() -> Result<mpsc::UnboundedReceiver<std::io::Result<Event>>, BoxError> {
    let (tx, rx) = mpsc::unbounded_channel();
    // Detached on purpose: the thread holds nothing the viewer needs back, and
    // it observes the dropped receiver within one poll timeout.
    std::thread::Builder::new()
        .name("rama-inspect-input".to_owned())
        .spawn(move || {
            while !tx.is_closed() {
                // A timeout rather than a blocking `read`, so quitting is not
                // waiting on a keypress that may never come.
                match event::poll(INPUT_POLL_TIMEOUT) {
                    Ok(false) => {}
                    Ok(true) => {
                        let event = event::read();
                        let failed = event.is_err();
                        if tx.send(event).is_err() || failed {
                            return;
                        }
                    }
                    Err(err) => {
                        _ = tx.send(Err(err));
                        return;
                    }
                }
            }
        })
        .context("spawn terminal input reader")?;
    Ok(rx)
}

/// What the event loop must do after a key press.
pub(super) enum Action {
    None,
    Redraw,
    Copy,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Normal,
    Filter(String),
    Help,
}

pub(super) struct AppState {
    view: View,
    list: ListState,
    mode: Mode,
    detail_scroll: u16,
    status: Option<String>,
}

impl AppState {
    pub(super) fn new(view: View) -> Self {
        let mut state = Self {
            view,
            list: ListState::default(),
            mode: Mode::Normal,
            detail_scroll: 0,
            status: None,
        };
        state.sync_list();
        state
    }

    fn sync_list(&mut self) {
        self.list
            .select((!self.view.is_empty()).then(|| self.view.cursor()));
    }

    fn moved(&mut self) -> Action {
        self.detail_scroll = 0;
        self.sync_list();
        Action::Redraw
    }

    // --- key handling ---

    pub(super) fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        self.status = None;
        match &self.mode {
            Mode::Filter(_) => self.on_key_filter(key.code),
            Mode::Help => {
                self.mode = Mode::Normal;
                Action::Redraw
            }
            Mode::Normal => self.on_key_normal(key.code),
        }
    }

    fn on_key_normal(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.view.select_next();
                self.moved()
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.view.select_prev();
                self.moved()
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.view.select_first();
                self.moved()
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.view.select_last();
                self.moved()
            }
            KeyCode::PageDown => {
                for _ in 0..10 {
                    self.view.select_next();
                }
                self.moved()
            }
            KeyCode::PageUp => {
                for _ in 0..10 {
                    self.view.select_prev();
                }
                self.moved()
            }
            KeyCode::Tab => {
                self.view.cycle_connection();
                self.moved()
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter(self.view.filter().to_owned());
                Action::Redraw
            }
            KeyCode::Char('+' | 'z') => {
                self.view.zoom(0.5);
                Action::Redraw
            }
            KeyCode::Char('-' | 'Z') => {
                self.view.zoom(2.0);
                Action::Redraw
            }
            KeyCode::Char('h') | KeyCode::Left => {
                self.view.pan(-0.25);
                Action::Redraw
            }
            KeyCode::Char('l') | KeyCode::Right => {
                self.view.pan(0.25);
                Action::Redraw
            }
            KeyCode::Char('0') => {
                self.view.reset_window();
                Action::Redraw
            }
            KeyCode::Char(' ') => {
                self.detail_scroll = self.detail_scroll.saturating_add(5);
                Action::Redraw
            }
            KeyCode::Char('n') => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
                Action::Redraw
            }
            KeyCode::Char('p') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
                Action::Redraw
            }
            KeyCode::Char('c' | 'y') => Action::Copy,
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                Action::Redraw
            }
            _ => Action::None,
        }
    }

    fn on_key_filter(&mut self, code: KeyCode) -> Action {
        let Mode::Filter(filter) = &mut self.mode else {
            return Action::None;
        };
        match code {
            // the filter stays applied either way: enter leaves the prompt,
            // escape leaves it too, and backspacing to empty clears it
            KeyCode::Esc | KeyCode::Enter => {
                self.mode = Mode::Normal;
                Action::Redraw
            }
            KeyCode::Backspace => {
                filter.pop();
                let filter = filter.clone();
                self.view.set_filter(filter);
                self.moved()
            }
            KeyCode::Char(c) => {
                filter.push(c);
                let filter = filter.clone();
                self.view.set_filter(filter);
                self.moved()
            }
            _ => Action::None,
        }
    }

    // --- rendering ---

    pub(super) fn render(&mut self, frame: &mut Frame) {
        let [header_area, list_area, detail_area, footer_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Percentage(45),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        self.render_header(frame, header_area);
        self.render_list(frame, list_area);
        self.render_detail(frame, detail_area);
        self.render_footer(frame, footer_area);
        if self.mode == Mode::Help {
            render_help(frame);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let timeline = self.view.timeline();
        let block = Block::new().borders(Borders::BOTTOM);
        let inner = block.inner(area);
        block.render(area, frame.buffer_mut());

        let [title_area, summary_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);

        let scope = match self.view.connection() {
            Some(index) => timeline.connections[index].label.to_string(),
            None if timeline.connections.len() > 1 => {
                format!("all {} connections", timeline.connections.len())
            }
            None => String::new(),
        };
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" {} ", timeline.format),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Rgb(0x3B, 0x7D, 0xDD))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                timeline.source.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if scope.is_empty() {
                    String::new()
                } else {
                    format!("  ·  {scope}")
                },
                Style::default().fg(Color::Cyan),
            ),
        ]))
        .render(title_area, frame.buffer_mut());

        let summary = timeline
            .summary
            .iter()
            .map(|field| format!("{}: {}", field.name, field.value))
            .collect::<Vec<_>>()
            .join("  ·  ");
        Paragraph::new(summary)
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true })
            .render(summary_area, frame.buffer_mut());
    }

    fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let (window_start, window_end) = self.view.window();
        let block = Block::bordered().title(format!(
            " timeline {} → {} ",
            util::duration(window_start),
            util::duration(window_end)
        ));
        let inner = block.inner(area);
        block.render(area, frame.buffer_mut());

        if self.view.is_empty() {
            Paragraph::new("no entries match the current filter")
                .style(Style::default().fg(Color::DarkGray))
                .render(inner, frame.buffer_mut());
            return;
        }

        let bar_width = usize::from(inner.width).saturating_sub(48).clamp(8, 40);
        let items: Vec<ListItem> = self
            .view
            .visible()
            .map(|entry| ListItem::new(self.entry_line(entry, bar_width)))
            .collect();
        let list = List::new(items)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always);
        StatefulWidget::render(list, inner, frame.buffer_mut(), &mut self.list);
    }

    fn entry_line(&self, entry: &Entry, bar_width: usize) -> Line<'static> {
        let color = level_color(entry.level);
        Line::from(vec![
            Span::styled(
                format!("{:>10}  ", util::duration(entry.start)),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(self.bar(entry, bar_width), Style::default().fg(color)),
            Span::raw(" "),
            Span::styled(
                format!("{:<6}", entry.badge.as_deref().unwrap_or("")),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(entry.label.to_string()),
            Span::styled(
                entry
                    .detail
                    .as_ref()
                    .map(|detail| format!("  {detail}"))
                    .unwrap_or_default(),
                Style::default().fg(Color::Gray),
            ),
        ])
    }

    /// The entry's extent within the visible window, as a bar of cells.
    fn bar(&self, entry: &Entry, width: usize) -> String {
        let Some((start, end)) = self.view.bar(entry) else {
            return " ".repeat(width);
        };
        let cells = width as f64;
        let from = ((start * cells) as usize).min(width.saturating_sub(1));
        let to = ((end * cells).ceil() as usize).clamp(from + 1, width);
        let mut bar = String::with_capacity(width);
        bar.push_str(&" ".repeat(from));
        bar.push_str(&"█".repeat(to - from));
        bar.push_str(&" ".repeat(width - to));
        bar
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" details ");
        let Some(entry) = self.view.selected() else {
            Paragraph::new("no entry selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(block)
                .render(area, frame.buffer_mut());
            return;
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", entry.badge.as_deref().unwrap_or("")),
                    Style::default()
                        .fg(level_color(entry.level))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    entry.label.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                format!(
                    "at {} · {}{}",
                    self.absolute_time(entry),
                    util::duration(entry.duration),
                    entry
                        .detail
                        .as_ref()
                        .map(|detail| format!(" · {detail}"))
                        .unwrap_or_default()
                ),
                Style::default().fg(Color::Gray),
            )),
        ];
        for section in &entry.sections {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                section.title.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )));
            lines.extend(section_lines(section));
        }

        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.detail_scroll, 0))
            .render(area, frame.buffer_mut());
    }

    fn absolute_time(&self, entry: &Entry) -> String {
        match self.view.timeline().timestamp_at(entry.start) {
            Some(at) => at.to_string(),
            None => format!("+{}", util::duration(entry.start)),
        }
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let footer = match (&self.mode, &self.status) {
            (Mode::Filter(filter), _) => format!(" /{filter}▏  enter apply · esc leave "),
            (_, Some(status)) => format!(" {status} "),
            _ => format!(
                " {shown}/{total} entries · j/k move · tab connection · / filter · z/Z zoom · h/l pan · c copy · ? help · q quit ",
                shown = self.view.len(),
                total = self.view.timeline().entries().len(),
            ),
        };
        Paragraph::new(footer)
            .style(Style::default().fg(Color::Gray))
            .render(area, frame.buffer_mut());
    }
}

fn section_lines(section: &Section) -> Vec<Line<'static>> {
    match &section.body {
        SectionBody::Fields(fields) => fields
            .iter()
            .map(|field| {
                Line::from(vec![
                    Span::styled(
                        format!("  {}: ", field.name),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(field.value.to_string()),
                ])
            })
            .collect(),
        SectionBody::Text(text) => text
            .lines()
            .map(|line| Line::raw(format!("  {line}")))
            .collect(),
        SectionBody::Unavailable(reason) => vec![Line::from(Span::styled(
            format!("  {reason}"),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))],
    }
}

fn level_color(level: Level) -> Color {
    match level {
        Level::Info => Color::Blue,
        Level::Success => Color::Green,
        Level::Warning => Color::Yellow,
        Level::Failure => Color::Red,
    }
}

fn render_help(frame: &mut Frame) {
    let help = [
        "j / k / ↑ / ↓     move selection",
        "g / G             first / last entry",
        "PgUp / PgDn       move by ten",
        "n / p / space     scroll details",
        "tab               next connection (or all)",
        "/                 filter, esc leaves it",
        "z / Z             zoom the time window in / out",
        "h / l / ← / →     pan the time window",
        "0                 show the whole capture",
        "c                 copy the selected entry (OSC 52)",
        "                  needs a terminal that allows it",
        "q / esc           quit",
    ];
    let area = frame.area();
    let width = 56.min(area.width);
    let height = (help.len() as u16 + 2).min(area.height);
    let area = Rect {
        x: (area.width.saturating_sub(width)) / 2,
        y: (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    Clear.render(area, frame.buffer_mut());
    Paragraph::new(help.map(Line::raw).to_vec())
        .block(Block::bordered().title(" keys "))
        .render(area, frame.buffer_mut());
}

/// Render the viewer's screen into plain text, for tests.
#[cfg(test)]
pub(super) fn render_to_string(state: &mut AppState, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|frame| state.render(frame)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<String>()
}

#[cfg(test)]
impl AppState {
    /// The view being shown, for assertions on selection and filtering.
    pub(super) fn view(&self) -> &View {
        &self.view
    }
}
