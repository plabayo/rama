//! ratatui-based reader for RSS / Atom feeds.
//!
//! Two screens: a scrollable list of entries and a per-entry detail view that
//! surfaces the body text plus any enclosures (podcast audio, etc.). Entries
//! can be appended live from a [`FeedStream`] so a large feed renders as it
//! arrives.
//!
//! The rendering and key handling live on [`AppState`], which holds no terminal
//! and is therefore unit-testable with ratatui's `TestBackend`. [`App`] wraps
//! it with the real terminal + event loop.

use rama::{
    error::{BoxError, ErrorContext as _},
    futures::{FutureExt as _, StreamExt as _},
    http::protocols::{
        html::{
            decode_entities,
            tokenizer::{EndTag, StartTag, Text, TokenSink, Tokenizer},
        },
        rss::{Feed, FeedItem, FeedStream},
    },
    telemetry::tracing,
};

use jiff::Timestamp;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    prelude::*,
    widgets::{Block, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap},
};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Run the reader over a live feed stream, appending entries as they parse.
pub(super) async fn run_streaming(stream: FeedStream) -> Result<(), BoxError> {
    let header = FeedHeader::from_stream(&stream);
    run_app(header, Vec::new(), Some(stream)).await
}

/// Run the reader over a fully-parsed feed.
pub(super) async fn run_buffered(feed: Feed) -> Result<(), BoxError> {
    let header = FeedHeader::from_feed(&feed);
    let items: Vec<FeedItem> = match feed {
        Feed::Rss2(f) => f.items.into_iter().map(FeedItem::from).collect(),
        Feed::Atom(f) => f.entries.into_iter().map(FeedItem::from).collect(),
    };
    run_app(header, items, None).await
}

async fn run_app(
    header: FeedHeader,
    items: Vec<FeedItem>,
    source: Option<FeedStream>,
) -> Result<(), BoxError> {
    let mut state = AppState::new(header);
    for item in items {
        state.push(item);
    }

    let terminal = ratatui::init();
    let _guard = TerminalGuard;
    let mut app = App {
        terminal,
        state,
        source,
    };
    app.event_loop().await
}

/// Restores the terminal out of raw mode / the alternate screen on drop, even
/// if the event loop returns early or panics.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

// ---------------------------------------------------------------------------
// App: terminal + event loop
// ---------------------------------------------------------------------------

struct App {
    terminal: DefaultTerminal,
    state: AppState,
    source: Option<FeedStream>,
}

impl App {
    async fn event_loop(&mut self) -> Result<(), BoxError> {
        let mut needs_redraw = true;
        loop {
            if self.drain_source() {
                needs_redraw = true;
            }
            self.state.loading = self.source.is_some();

            if needs_redraw {
                let state = &mut self.state;
                self.terminal
                    .draw(|frame| state.render(frame))
                    .context("draw feed reader")?;
                needs_redraw = false;
            }

            if event::poll(Duration::ZERO).context("poll terminal events")?
                && let Event::Key(key) = event::read().context("read terminal event")?
                && key.kind == KeyEventKind::Press
            {
                match self.state.on_key(key) {
                    Action::Quit => return Ok(()),
                    Action::Open(url) => {
                        open_url(&url);
                        needs_redraw = true;
                    }
                    Action::Redraw => needs_redraw = true,
                    Action::None => {}
                }
            }

            let tick = if self.source.is_some() {
                Duration::from_millis(16)
            } else {
                Duration::from_millis(50)
            };
            tokio::time::sleep(tick).await;
        }
    }

    /// Drain whatever feed items are ready without blocking. Returns true if
    /// anything changed (items pushed or stream completed).
    fn drain_source(&mut self) -> bool {
        let Some(stream) = self.source.as_mut() else {
            return false;
        };
        let mut changed = false;
        // Bound the work per tick so a fast feed can't starve rendering/input.
        for _ in 0..128 {
            match stream.next().now_or_never() {
                Some(Some(Ok(item))) => {
                    self.state.push(item);
                    changed = true;
                }
                Some(Some(Err(err))) => {
                    tracing::debug!("skip unparseable feed item: {err}");
                    changed = true;
                }
                Some(None) => {
                    self.source = None;
                    changed = true;
                    break;
                }
                None => break,
            }
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// AppState: data + rendering + key handling (terminal-free, testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedFormat {
    Rss,
    Atom,
}

impl FeedFormat {
    fn badge(self) -> &'static str {
        match self {
            Self::Rss => " RSS ",
            Self::Atom => " ATOM ",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Rss => Color::Rgb(0xF2, 0x6E, 0x22),
            Self::Atom => Color::Rgb(0x3B, 0x7D, 0xDD),
        }
    }
}

#[derive(Debug, Clone)]
struct FeedHeader {
    title: String,
    subtitle: Option<String>,
    format: FeedFormat,
}

impl FeedHeader {
    fn from_stream(stream: &FeedStream) -> Self {
        Self {
            title: nonempty(stream.title()).unwrap_or_else(|| "(untitled feed)".to_owned()),
            subtitle: stream.description().and_then(plain_nonempty).or_else(|| {
                stream
                    .link()
                    .and_then(|uri| nonempty(uri.as_str().as_ref()))
            }),
            format: match stream {
                FeedStream::Atom(_) => FeedFormat::Atom,
                FeedStream::Rss2(_) => FeedFormat::Rss,
            },
        }
    }

    fn from_feed(feed: &Feed) -> Self {
        Self {
            title: nonempty(feed.title()).unwrap_or_else(|| "(untitled feed)".to_owned()),
            subtitle: feed
                .description()
                .and_then(plain_nonempty)
                .or_else(|| feed.link().and_then(|uri| nonempty(uri.as_str().as_ref()))),
            format: if feed.is_rss2() {
                FeedFormat::Rss
            } else {
                FeedFormat::Atom
            },
        }
    }
}

/// Outcome of handling a key press.
enum Action {
    None,
    Redraw,
    Open(String),
    Quit,
}

struct AppState {
    header: FeedHeader,
    items: Vec<FeedItem>,
    list: ListState,
    screen: Screen,
    detail_scroll: u16,
    loading: bool,
}

impl AppState {
    fn new(header: FeedHeader) -> Self {
        Self {
            header,
            items: Vec::new(),
            list: ListState::default(),
            screen: Screen::List,
            detail_scroll: 0,
            loading: false,
        }
    }

    fn push(&mut self, item: FeedItem) {
        self.items.push(item);
        if self.list.selected().is_none() {
            self.list.select(Some(0));
        }
    }

    fn selected_index(&self) -> usize {
        self.list.selected().unwrap_or(0)
    }

    fn selected(&self) -> Option<&FeedItem> {
        self.items.get(self.selected_index())
    }

    // --- key handling ---

    fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        match self.screen {
            Screen::List => self.on_key_list(key.code),
            Screen::Detail => self.on_key_detail(key.code),
        }
    }

    fn on_key_list(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.select_next();
                Action::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.select_prev();
                Action::Redraw
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.select_first();
                Action::Redraw
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.select_last();
                Action::Redraw
            }
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if !self.items.is_empty() {
                    self.screen = Screen::Detail;
                    self.detail_scroll = 0;
                }
                Action::Redraw
            }
            KeyCode::Char('o') => self.open_selected_link(),
            _ => Action::None,
        }
    }

    fn on_key_detail(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => {
                self.screen = Screen::List;
                Action::Redraw
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
                Action::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
                Action::Redraw
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.detail_scroll = 0;
                Action::Redraw
            }
            KeyCode::Char('n') => {
                self.select_next();
                self.detail_scroll = 0;
                Action::Redraw
            }
            KeyCode::Char('p') => {
                self.select_prev();
                self.detail_scroll = 0;
                Action::Redraw
            }
            KeyCode::Char('o') => self.open_selected_link(),
            KeyCode::Char('e') => self.open_selected_enclosure(),
            _ => Action::None,
        }
    }

    fn select_next(&mut self) {
        if self.items.is_empty() {
            return;
        }
        let next = self
            .list
            .selected()
            .map_or(0, |i| (i + 1).min(self.items.len() - 1));
        self.list.select(Some(next));
    }

    fn select_prev(&mut self) {
        if self.items.is_empty() {
            return;
        }
        let prev = self.list.selected().map_or(0, |i| i.saturating_sub(1));
        self.list.select(Some(prev));
    }

    fn select_first(&mut self) {
        if !self.items.is_empty() {
            self.list.select(Some(0));
        }
    }

    fn select_last(&mut self) {
        if !self.items.is_empty() {
            self.list.select(Some(self.items.len() - 1));
        }
    }

    fn open_selected_link(&self) -> Action {
        match self.selected().and_then(FeedItem::link) {
            Some(url) => Action::Open(url.to_string()),
            None => Action::None,
        }
    }

    fn open_selected_enclosure(&self) -> Action {
        match self
            .selected()
            .and_then(|item| item.enclosures().next().map(|e| e.url.to_string()))
        {
            Some(url) => Action::Open(url),
            None => self.open_selected_link(),
        }
    }

    // --- rendering ---

    fn render(&mut self, frame: &mut Frame) {
        match self.screen {
            Screen::List => self.render_list(frame),
            Screen::Detail => self.render_detail(frame),
        }
    }

    fn render_list(&mut self, frame: &mut Frame) {
        let area = frame.area();

        // Size the header to fit the (wrapped) description, but never let it
        // crowd out the list — keep at least a few entry rows.
        let subtitle_rows = match &self.header.subtitle {
            Some(subtitle) => {
                let budget = area.height.saturating_sub(1 + 1 + 1 + 3);
                wrapped_height(subtitle, area.width).clamp(1, budget.max(1))
            }
            None => 0,
        };
        let header_height = 1 + subtitle_rows + 1; // title + subtitle + bottom border

        let [header_area, list_area, footer_area] = Layout::vertical([
            Constraint::Length(header_height),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        self.render_header(frame, header_area);

        let items: Vec<ListItem> = self
            .items
            .iter()
            .map(|item| {
                let date = fmt_date(item.published().or_else(|| item.updated()));
                let title = item.title().unwrap_or("(untitled)");
                let line = Line::from(vec![
                    Span::styled(
                        format!("{date:>10}  "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(title.to_owned()),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always);
        StatefulWidget::render(list, list_area, frame.buffer_mut(), &mut self.list);

        let footer = format!(
            " {count} entr{plural}{loading}   j/k move · enter open · o browser · q quit ",
            count = self.items.len(),
            plural = if self.items.len() == 1 { "y" } else { "ies" },
            loading = if self.loading { " · loading…" } else { "" },
        );
        Paragraph::new(footer)
            .style(Style::default().fg(Color::Gray))
            .render(footer_area, frame.buffer_mut());
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let block = Block::new().borders(Borders::BOTTOM);
        let inner = block.inner(area);
        block.render(area, frame.buffer_mut());

        let [title_area, subtitle_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);

        let title = Line::from(vec![
            Span::styled(
                self.header.format.badge(),
                Style::default()
                    .fg(Color::Black)
                    .bg(self.header.format.color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                self.header.title.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]);
        Paragraph::new(title).render(title_area, frame.buffer_mut());

        // Wrap the description onto the next line(s) instead of clipping it.
        if let Some(subtitle) = &self.header.subtitle {
            Paragraph::new(subtitle.clone())
                .style(Style::default().fg(Color::Gray))
                .wrap(Wrap { trim: true })
                .render(subtitle_area, frame.buffer_mut());
        }
    }

    fn render_detail(&self, frame: &mut Frame) {
        let [body_area, footer_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(frame.area());

        let block = Block::bordered().title(format!(" {} ", self.header.title));

        let Some(item) = self.items.get(self.selected_index()) else {
            Paragraph::new("no entry selected")
                .block(block)
                .render(body_area, frame.buffer_mut());
            return;
        };

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            item.title().unwrap_or("(untitled)").to_owned(),
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )));
        lines.push(Line::raw(""));

        if let Some(ts) = item.published() {
            lines.push(meta("published", &fmt_datetime(ts)));
        }
        if let Some(ts) = item.updated() {
            lines.push(meta("updated", &fmt_datetime(ts)));
        }
        let authors: Vec<&str> = item.authors().collect();
        if !authors.is_empty() {
            lines.push(meta("by", &authors.join(", ")));
        }
        let topics: Vec<&str> = item.categories().collect();
        if !topics.is_empty() {
            lines.push(meta("topics", &topics.join(", ")));
        }
        if let Some(link) = item.link() {
            lines.push(meta("link", &link.to_string()));
        }
        for enc in item.enclosures() {
            let mime = enc.mime.unwrap_or("?");
            let detail = match enc.length {
                Some(len) => format!("{} [{}, {}]", enc.url, mime, human_size(len)),
                None => format!("{} [{}]", enc.url, mime),
            };
            lines.push(meta("media", &detail));
        }

        if let Some(raw) = item.content().or_else(|| item.summary()) {
            let body = html_to_lines(raw);
            if !body.is_empty() {
                lines.push(Line::raw(""));
                lines.extend(body);
            }
        }

        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.detail_scroll, 0))
            .render(body_area, frame.buffer_mut());

        let position = format!(
            " {}/{} ",
            self.selected_index() + 1,
            self.items.len().max(1)
        );
        let footer =
            format!("{position}  j/k scroll · n/p entry · o link · e media · esc back · q quit ",);
        Paragraph::new(footer)
            .style(Style::default().fg(Color::Gray))
            .render(footer_area, frame.buffer_mut());
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn meta(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key}: "), Style::default().fg(Color::Cyan)),
        Span::raw(value.to_owned()),
    ])
}

fn nonempty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Flatten (possibly HTML) text to a single whitespace-collapsed plain line —
/// used for the compact feed-description blurb in the list header.
fn plain_nonempty(s: &str) -> Option<String> {
    nonempty(&html_to_plain(s))
}

fn html_to_plain(input: &str) -> String {
    let joined = html_to_lines(input)
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ");
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Approximate the number of rows `text` needs when word-wrapped to `width`
/// (matching ratatui's `Wrap { trim: true }`), so the header can be sized to
/// fit the description instead of clipping it.
fn wrapped_height(text: &str, width: u16) -> u16 {
    let width = width.max(1) as usize;
    let mut rows: u16 = 1;
    let mut col: usize = 0;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if col != 0 && col + 1 + len > width {
            rows = rows.saturating_add(1);
            col = 0;
        }
        if col == 0 {
            // A word longer than the line wraps across several rows.
            let extra_rows = len.saturating_sub(1) / width;
            rows = rows.saturating_add(extra_rows as u16);
            col = len - extra_rows * width;
        } else {
            col += 1 + len;
        }
    }
    rows
}

fn fmt_date(ts: Option<Timestamp>) -> String {
    match ts {
        Some(ts) => ts
            .to_string()
            .split('T')
            .next()
            .unwrap_or_default()
            .to_owned(),
        None => String::new(),
    }
}

fn fmt_datetime(ts: Timestamp) -> String {
    let s = ts.to_string();
    let no_frac = s.split('.').next().unwrap_or(&s);
    no_frac.trim_end_matches('Z').replace('T', " ")
}

fn human_size(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let n_f = n as f64;
    if n_f >= GB {
        format!("{:.1} GB", n_f / GB)
    } else if n_f >= MB {
        format!("{:.1} MB", n_f / MB)
    } else if n_f >= KB {
        format!("{:.1} KB", n_f / KB)
    } else {
        format!("{n} B")
    }
}

/// Render (possibly HTML) feed body text into styled terminal lines.
///
/// A small, dependency-free HTML-to-[`Line`] converter — not a real HTML
/// engine. It applies the formatting feeds actually use: paragraphs, line
/// breaks, headings, lists, blockquotes, inline emphasis / code, and links
/// (whose target is appended in parentheses since a terminal can't click).
/// `<script>` / `<style>` content and unknown tags are dropped, and common
/// entities are decoded. Width-wrapping is left to the rendering `Paragraph`,
/// so each returned line is a single logical line.
fn html_to_lines(input: &str) -> Vec<Line<'static>> {
    let mut renderer = HtmlRenderer::default();
    renderer.run(input);
    renderer.finish()
}

#[derive(Clone, Copy)]
enum ListMarker {
    Bullet,
    Number(u32),
}

#[derive(Default)]
struct HtmlRenderer {
    lines: Vec<Line<'static>>,
    spans: Vec<Span<'static>>,
    style: Style,
    style_stack: Vec<Style>,
    href_stack: Vec<Option<String>>,
    list_stack: Vec<ListMarker>,
    in_pre: usize,
    skip_text: usize,
    line_has_content: bool,
}

impl HtmlRenderer {
    fn run(&mut self, input: &str) {
        if Tokenizer::new().tokenize(input.as_bytes(), self).is_err() {
            self.text(&decode_entities(input));
        }
    }

    fn open_tag(&mut self, name: &str, tag: &StartTag<'_>) {
        match name {
            "script" | "style" => self.skip_text += 1,
            "br" => self.flush_line(),
            "hr" => self.rule(),
            "p" | "div" | "section" | "article" | "header" | "footer" | "figure" | "figcaption"
            | "main" | "aside" | "table" | "tr" => self.ensure_blank(),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.ensure_blank();
                self.push_style(self.style.add_modifier(Modifier::BOLD));
            }
            "b" | "strong" => self.push_style(self.style.add_modifier(Modifier::BOLD)),
            "i" | "em" | "cite" | "dfn" => {
                self.push_style(self.style.add_modifier(Modifier::ITALIC));
            }
            "u" | "ins" => self.push_style(self.style.add_modifier(Modifier::UNDERLINED)),
            "s" | "strike" | "del" => {
                self.push_style(self.style.add_modifier(Modifier::CROSSED_OUT));
            }
            "code" | "tt" | "kbd" | "samp" | "var" => self.push_style(self.style.fg(Color::Cyan)),
            "pre" => {
                self.ensure_blank();
                self.in_pre += 1;
                self.push_style(self.style.fg(Color::Cyan));
            }
            "blockquote" => {
                self.ensure_blank();
                self.push_style(self.style.fg(Color::Gray).add_modifier(Modifier::ITALIC));
            }
            "ul" => {
                self.ensure_blank();
                self.list_stack.push(ListMarker::Bullet);
            }
            "ol" => {
                self.ensure_blank();
                self.list_stack.push(ListMarker::Number(1));
            }
            "li" => self.start_list_item(),
            "a" => {
                self.href_stack.push(extract_attr(tag, b"href"));
                self.push_style(
                    self.style
                        .fg(Color::Blue)
                        .add_modifier(Modifier::UNDERLINED),
                );
            }
            _ => {}
        }
    }

    fn close_tag(&mut self, name: &str) {
        match name {
            "script" | "style" => self.skip_text = self.skip_text.saturating_sub(1),
            "p" | "div" | "section" | "article" | "header" | "footer" | "figure" | "figcaption"
            | "main" | "aside" | "table" | "tr" => self.ensure_blank(),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" => {
                self.pop_style();
                self.ensure_blank();
            }
            "b" | "strong" | "i" | "em" | "cite" | "dfn" | "u" | "ins" | "s" | "strike" | "del"
            | "code" | "tt" | "kbd" | "samp" | "var" => self.pop_style(),
            "pre" => {
                self.in_pre = self.in_pre.saturating_sub(1);
                self.pop_style();
                self.ensure_blank();
            }
            "ul" | "ol" => {
                self.list_stack.pop();
                self.ensure_blank();
            }
            "li" => self.flush_line(),
            "a" => {
                let href = self.href_stack.pop().flatten();
                self.pop_style();
                if let Some(href) = href.filter(|h| !h.is_empty()) {
                    self.spans.push(Span::styled(
                        format!(" ({href})"),
                        Style::default().add_modifier(Modifier::DIM),
                    ));
                    self.line_has_content = true;
                }
            }
            _ => {}
        }
    }

    fn push_style(&mut self, style: Style) {
        self.style_stack.push(self.style);
        self.style = style;
    }

    fn pop_style(&mut self) {
        if let Some(style) = self.style_stack.pop() {
            self.style = style;
        }
    }

    fn start_list_item(&mut self) {
        if !self.spans.is_empty() {
            self.flush_line();
        }
        let depth = self.list_stack.len().max(1);
        let marker = match self.list_stack.last_mut() {
            Some(ListMarker::Number(n)) => {
                let marker = format!("{n}. ");
                *n += 1;
                marker
            }
            _ => "• ".to_owned(),
        };
        self.spans.push(Span::styled(
            format!("{}{marker}", "  ".repeat(depth - 1)),
            Style::default().add_modifier(Modifier::DIM),
        ));
        // The marker carries its own trailing space; trim the item's leading ws.
        self.line_has_content = false;
    }

    fn rule(&mut self) {
        self.ensure_blank();
        self.lines.push(Line::from(Span::styled(
            "────────",
            Style::default().fg(Color::DarkGray),
        )));
        self.line_has_content = false;
    }

    /// Appends already-decoded text (UTF-8, entities resolved) to the current
    /// line, collapsing whitespace outside `<pre>`.
    fn text(&mut self, text: &str) {
        if self.skip_text > 0 {
            return;
        }

        if self.in_pre > 0 {
            for (i, piece) in text.split('\n').enumerate() {
                if i > 0 {
                    self.flush_line();
                }
                if !piece.is_empty() {
                    self.spans.push(Span::styled(piece.to_owned(), self.style));
                    self.line_has_content = true;
                }
            }
            return;
        }

        // Collapse runs of whitespace to a single space, trimming any leading
        // whitespace at the start of a line.
        let mut buf = String::new();
        let mut prev_ws = !self.line_has_content;
        for ch in text.chars() {
            if ch.is_whitespace() {
                if !prev_ws {
                    buf.push(' ');
                    prev_ws = true;
                }
            } else {
                buf.push(ch);
                prev_ws = false;
            }
        }
        if buf.is_empty() || (buf == " " && !self.line_has_content) {
            return;
        }
        let has_content = buf.contains(|c: char| !c.is_whitespace());
        self.spans.push(Span::styled(buf, self.style));
        if has_content {
            self.line_has_content = true;
        }
    }

    fn flush_line(&mut self) {
        let spans = std::mem::take(&mut self.spans);
        self.lines.push(Line::from(spans));
        self.line_has_content = false;
    }

    fn ensure_blank(&mut self) {
        if !self.spans.is_empty() {
            self.flush_line();
        }
        if self.lines.last().is_some_and(|line| !line_is_empty(line)) {
            self.lines.push(Line::from(""));
        }
    }

    fn finish(mut self) -> Vec<Line<'static>> {
        if !self.spans.is_empty() {
            self.flush_line();
        }
        while self.lines.first().is_some_and(line_is_empty) {
            self.lines.remove(0);
        }
        while self.lines.last().is_some_and(line_is_empty) {
            self.lines.pop();
        }
        self.lines
    }
}

impl TokenSink for HtmlRenderer {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let name = tag_name(tag.name());
        if name.is_empty() {
            return;
        }
        self.open_tag(&name, tag);
        if tag.is_self_closing() {
            self.close_tag(&name);
        }
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        let name = tag_name(tag.name());
        if !name.is_empty() {
            self.close_tag(&name);
        }
    }

    fn text(&mut self, text: &Text<'_>) {
        Self::text(self, &text.decoded());
    }
}

fn line_is_empty(line: &Line<'_>) -> bool {
    line.spans.iter().all(|span| span.content.trim().is_empty())
}

fn tag_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_ascii_lowercase()
}

/// Extract a decoded attribute value from a tokenized start tag.
fn extract_attr(tag: &StartTag<'_>, name: &[u8]) -> Option<String> {
    tag.attributes()
        .find(|attr| attr.name().eq_ignore_ascii_case(name))
        .map(|attr| attr.value_decoded().into_owned())
}

fn open_url(url: &str) {
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };

    if let Err(err) = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        tracing::debug!("failed to open url {url} in browser: {err}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::Body;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    const RSS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Rust Podcast</title>
    <link>https://example.com</link>
    <description>All things Rust</description>
    <item>
      <title>Episode One</title>
      <link>https://example.com/ep1</link>
      <description>The very first episode.</description>
      <pubDate>Tue, 02 Jan 2024 08:00:00 GMT</pubDate>
      <enclosure url="https://example.com/ep1.mp3" length="12345678" type="audio/mpeg"/>
    </item>
    <item>
      <title>Episode Two</title>
      <link>https://example.com/ep2</link>
      <description>The second episode.</description>
      <pubDate>Tue, 09 Jan 2024 08:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"#;

    const ATOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Blog</title>
  <subtitle>thoughts in atoms</subtitle>
  <id>urn:uuid:feed</id>
  <updated>2024-01-02T08:00:00Z</updated>
  <link href="https://atom.example.com"/>
  <entry>
    <title>Hello Atom</title>
    <id>urn:uuid:entry-1</id>
    <updated>2024-01-02T08:00:00Z</updated>
    <published>2024-01-02T08:00:00Z</published>
    <link href="https://atom.example.com/hello"/>
    <summary>An atom entry summary.</summary>
  </entry>
</feed>"#;

    async fn feed_from(xml: &'static str) -> Feed {
        Feed::from_body(Body::from(xml)).await.expect("parse feed")
    }

    fn state_from(feed: Feed) -> AppState {
        let header = FeedHeader::from_feed(&feed);
        let mut state = AppState::new(header);
        let items: Vec<FeedItem> = match feed {
            Feed::Rss2(f) => f.items.into_iter().map(FeedItem::from).collect(),
            Feed::Atom(f) => f.entries.into_iter().map(FeedItem::from).collect(),
        };
        for item in items {
            state.push(item);
        }
        state
    }

    fn render_to_string(state: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| state.render(frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[tokio::test]
    async fn rss_list_renders_title_and_entries() {
        let mut state = state_from(feed_from(RSS).await);
        let screen = render_to_string(&mut state, 80, 20);
        assert!(screen.contains("RSS"), "format badge missing:\n{screen}");
        assert!(
            screen.contains("Rust Podcast"),
            "feed title missing:\n{screen}"
        );
        assert!(screen.contains("Episode One"), "entry 1 missing:\n{screen}");
        assert!(screen.contains("Episode Two"), "entry 2 missing:\n{screen}");
        assert!(screen.contains("2 entries"), "count missing:\n{screen}");
    }

    #[tokio::test]
    async fn rss_detail_shows_body_and_enclosure() {
        let mut state = state_from(feed_from(RSS).await);
        // Enter detail on the first entry.
        assert!(matches!(state.on_key(key(KeyCode::Enter)), Action::Redraw));
        assert_eq!(state.screen, Screen::Detail);

        let screen = render_to_string(&mut state, 100, 24);
        assert!(screen.contains("Episode One"), "title missing:\n{screen}");
        assert!(
            screen.contains("The very first episode."),
            "body missing:\n{screen}"
        );
        assert!(
            screen.contains("example.com/ep1.mp3"),
            "enclosure url missing:\n{screen}"
        );
        assert!(
            screen.contains("audio/mpeg"),
            "enclosure mime missing:\n{screen}"
        );
    }

    #[tokio::test]
    async fn navigation_moves_selection() {
        let mut state = state_from(feed_from(RSS).await);
        assert_eq!(state.selected_index(), 0);
        state.on_key(key(KeyCode::Char('j')));
        assert_eq!(state.selected_index(), 1);
        // clamped at the end
        state.on_key(key(KeyCode::Char('j')));
        assert_eq!(state.selected_index(), 1);
        state.on_key(key(KeyCode::Char('k')));
        assert_eq!(state.selected_index(), 0);
    }

    #[tokio::test]
    async fn open_returns_selected_link() {
        let mut state = state_from(feed_from(RSS).await);
        match state.on_key(key(KeyCode::Char('o'))) {
            Action::Open(url) => assert_eq!(url, "https://example.com/ep1"),
            _ => panic!("expected Action::Open"),
        }
    }

    #[tokio::test]
    async fn ctrl_c_quits() {
        let mut state = state_from(feed_from(RSS).await);
        let event = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(state.on_key(event), Action::Quit));
    }

    #[tokio::test]
    async fn atom_feed_renders() {
        let mut state = state_from(feed_from(ATOM).await);
        let screen = render_to_string(&mut state, 80, 20);
        assert!(screen.contains("ATOM"), "atom badge missing:\n{screen}");
        assert!(
            screen.contains("Atom Blog"),
            "atom title missing:\n{screen}"
        );
        assert!(
            screen.contains("Hello Atom"),
            "atom entry missing:\n{screen}"
        );
    }

    fn lines_text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn html_to_lines_renders_inline_styles_and_links() {
        let lines =
            html_to_lines(r#"<p>Hello <b>bold</b> &amp; <a href="https://x.test">link</a></p>"#);
        let text = lines_text(&lines);
        assert!(text.contains("Hello bold & link"), "text: {text:?}");
        // a terminal can't click, so the target is surfaced inline
        assert!(
            text.contains("(https://x.test)"),
            "href not appended: {text:?}"
        );

        let bold = lines
            .iter()
            .flat_map(|line| &line.spans)
            .find(|span| span.content.as_ref() == "bold")
            .expect("bold span present");
        assert!(
            bold.style.add_modifier.contains(Modifier::BOLD),
            "bold text is not styled bold"
        );
    }

    #[test]
    fn html_to_lines_lists_breaks_entities_and_drops_script() {
        let lines = html_to_lines(
            "<ul><li>one</li><li>two</li></ul><script>alert(1)</script>line1<br>line2 &mdash; end",
        );
        let text = lines_text(&lines);
        assert!(text.contains("• one"), "first bullet missing: {text:?}");
        assert!(text.contains("• two"), "second bullet missing: {text:?}");
        assert!(!text.contains("alert"), "script content leaked: {text:?}");
        assert!(
            text.contains("line1\nline2 — end"),
            "br/entity not handled: {text:?}"
        );
    }

    #[test]
    fn html_to_lines_tokenizes_quoted_gt_and_decodes_href() {
        let lines =
            html_to_lines(r#"<p>See <a href="https://x.test/?q=a&gt;b">link</a> after</p>"#);
        let text = lines_text(&lines);
        assert!(
            text.contains("See link (https://x.test/?q=a>b) after"),
            "quoted gt or href entity mishandled: {text:?}"
        );
    }

    #[test]
    fn html_to_lines_handles_partial_html_without_panicking() {
        let lines = html_to_lines("<p>before <strong>bold<a href=\"https://x.test?q=1&gt;2\"");
        let text = lines_text(&lines);
        assert!(text.contains("before bold"), "text missing: {text:?}");
        assert!(!text.contains("<strong>"), "raw tag leaked: {text:?}");
    }

    #[test]
    fn html_to_plain_strips_tags_and_collapses_whitespace() {
        assert_eq!(
            html_to_plain("<p>Hello  &amp; <b>world</b></p>\n<p>again</p>"),
            "Hello & world again"
        );
    }

    #[test]
    fn wrapped_height_counts_rows() {
        assert_eq!(wrapped_height("hello world", 20), 1);
        assert_eq!(wrapped_height("hello world", 6), 2);
        assert_eq!(wrapped_height("", 10), 1);
        // a word longer than the width spills onto extra rows
        assert_eq!(wrapped_height("abcdefghij", 5), 2);
    }
}
