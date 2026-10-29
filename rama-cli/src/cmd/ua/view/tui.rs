//! Terminal interaction over already loaded profiles.

use super::{
    display::{Layer, Row, ScopeLabel, variant_weight},
    render::{self, DIM, KEY, Lines, NUMBER, SECTION},
};
use rama::{
    error::{BoxError, ErrorContext as _},
    http::fingerprint::{HttpRequestInput, Ja4H},
    tls::fingerprint::Ja4,
    ua::profile::analysis::profile::AnalyzedProfileScope,
    utils::octets::kib,
};
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Clear, List, ListItem, ListState, Paragraph, Row as TableRow, Table,
        TableState, Tabs, Wrap,
    },
};

pub(super) fn run(rows: Vec<Row>, source: String) -> Result<(), BoxError> {
    App::new(rows, source).run()
}

const SELECTED: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
const SELECTED_UNFOCUSED: Style = Style::new().add_modifier(Modifier::REVERSED);
const FOCUSED_BORDER: Style = Style::new().fg(Color::Cyan);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Profiles,
    Scopes,
}

/// Scope listing of the selected profile, rebuilt whenever the selection changes.
struct ProfileView {
    row: usize,
    layers: Vec<Vec<(usize, ScopeLabel)>>,
    overview: Vec<Line<'static>>,
}

struct App {
    rows: Vec<Row>,
    visible: Vec<usize>,
    selected: usize,
    filter: String,
    editing: bool,
    source: String,
    focus: Focus,
    layer: usize,
    scope: usize,
    variant: usize,
    scroll: u16,
    help: bool,
    view: Option<ProfileView>,
}

impl App {
    fn new(rows: Vec<Row>, source: String) -> Self {
        let mut app = Self {
            visible: (0..rows.len()).collect(),
            rows,
            selected: 0,
            filter: String::new(),
            editing: false,
            source,
            focus: Focus::Profiles,
            layer: 0,
            scope: 0,
            variant: 0,
            scroll: 0,
            help: false,
            view: None,
        };
        app.sync();
        app
    }

    fn filter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| row.matches(&needle).then_some(index))
            .collect();
        self.selected = 0;
        self.sync();
    }

    /// Rebuild the cached view when the selected profile changed.
    fn sync(&mut self) {
        let row = self.visible.get(self.selected).copied();
        if self.view.as_ref().map(|view| view.row) == row {
            return;
        }
        self.view = row.map(|index| profile_view(index, &self.rows[index]));
        self.scope = 0;
        self.variant = 0;
        self.scroll = 0;
    }

    fn layer(&self) -> Layer {
        Layer::ALL[self.layer]
    }

    fn scopes(&self) -> &[(usize, ScopeLabel)] {
        self.view
            .as_ref()
            .map_or(&[], |view| view.layers[self.layer].as_slice())
    }

    fn set_layer(&mut self, layer: usize) {
        self.layer = layer.min(Layer::ALL.len() - 1);
        self.scope = 0;
        self.variant = 0;
        self.scroll = 0;
    }

    /// Step to the next layer with observed scopes, keeping the overview reachable.
    fn step_layer(&mut self, forward: bool) {
        let count = Layer::ALL.len();
        let mut layer = self.layer;
        for _ in 0..count {
            layer = if forward {
                (layer + 1) % count
            } else {
                (layer + count - 1) % count
            };
            let empty = self
                .view
                .as_ref()
                .is_none_or(|view| view.layers[layer].is_empty());
            if layer == 0 || !empty {
                break;
            }
        }
        self.set_layer(layer);
    }

    fn variants(&self) -> usize {
        self.selected_scope()
            .map_or(0, |scope| scope.observations.variants.len())
    }

    fn selected_scope(&self) -> Option<&AnalyzedProfileScope> {
        let (index, _) = self.scopes().get(self.scope)?;
        let row = self.visible.get(self.selected)?;
        self.rows[*row]
            .profile
            .captured
            .as_ref()?
            .scopes
            .get(*index)
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
        if self.help {
            self.help = !matches!(key.code, KeyCode::Esc | KeyCode::Char('?' | 'q'));
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('/') => self.editing = true,
            KeyCode::Esc => {
                self.filter.clear();
                self.filter();
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Profiles => Focus::Scopes,
                    Focus::Scopes => Focus::Profiles,
                };
            }
            KeyCode::Enter if self.focus == Focus::Profiles => {
                self.focus = Focus::Scopes;
                if self.layer == 0 {
                    self.step_layer(true);
                }
            }
            KeyCode::Right | KeyCode::Char('l') => self.step_layer(true),
            KeyCode::Left | KeyCode::Char('h') => self.step_layer(false),
            KeyCode::Char(digit @ '1'..='8') => self.set_layer(digit as usize - '1' as usize),
            KeyCode::Char(']') => {
                self.variant = (self.variant + 1).min(self.variants().saturating_sub(1));
                self.scroll = 0;
            }
            KeyCode::Char('[') => {
                self.variant = self.variant.saturating_sub(1);
                self.scroll = 0;
            }
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::Home => self.step(isize::MIN),
            KeyCode::End => self.step(isize::MAX),
            _ => (),
        }
        false
    }

    fn step(&mut self, delta: isize) {
        let (position, length) = match self.focus {
            Focus::Profiles => (self.selected, self.visible.len()),
            Focus::Scopes => (self.scope, self.scopes().len()),
        };
        let next = position
            .saturating_add_signed(delta)
            .min(length.saturating_sub(1));
        match self.focus {
            Focus::Profiles => {
                self.selected = next;
                self.sync();
            }
            Focus::Scopes => {
                self.scope = next;
                self.variant = 0;
                self.scroll = 0;
            }
        }
    }

    fn draw(&self, frame: &mut Frame<'_>) {
        let [title, body, help] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        self.draw_title(frame, title);
        let [list, details] = if body.width >= 110 {
            Layout::horizontal([Constraint::Length(56), Constraint::Min(1)]).areas(body)
        } else {
            Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)]).areas(body)
        };
        self.draw_profiles(frame, list);
        self.draw_details(frame, details);
        frame.render_widget(
            Paragraph::new(hints(&[
                ("↑↓", "select"),
                ("Tab", "focus"),
                ("←→ 1-8", "layer"),
                ("[ ]", "variant"),
                ("PgUp/PgDn", "scroll"),
                ("/", "filter"),
                ("?", "help"),
                ("q", "quit"),
            ])),
            help,
        );
        if self.help {
            draw_help(frame, frame.area());
        }
    }

    fn draw_title(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut spans = vec![
            Span::styled(
                " rama ua view ",
                Style::new().fg(Color::Black).bg(Color::Cyan),
            ),
            Span::styled(format!("  {}  ", self.source), DIM),
            Span::styled(
                format!("{}/{} profiles", self.visible.len(), self.rows.len()),
                NUMBER,
            ),
            Span::styled("  filter ", DIM),
        ];
        spans.push(if self.editing {
            Span::styled(
                format!("{}▏", self.filter),
                Style::new().fg(Color::White).bg(Color::DarkGray),
            )
        } else if self.filter.is_empty() {
            Span::styled("(press /)", DIM)
        } else {
            Span::styled(self.filter.clone(), KEY)
        });
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_profiles(&self, frame: &mut Frame<'_>, area: Rect) {
        let header = TableRow::new(
            ["client", "ver", "platform", "dev"]
                .into_iter()
                .map(Cell::from)
                .chain(Layer::PROTOCOLS.iter().map(|layer| {
                    Cell::from(Span::styled(layer.chip(), Style::new().fg(layer.color())))
                }))
                .chain([Cell::from(Line::from("obs").right_aligned())]),
        )
        .style(Style::new().add_modifier(Modifier::BOLD));
        let rows = self.visible.iter().map(|index| {
            let row = &self.rows[*index];
            TableRow::new(
                [
                    Cell::from(Span::styled(
                        row.client.clone(),
                        Style::new().fg(client_color(&row.client)),
                    )),
                    Cell::from(Span::styled(
                        row.version.clone(),
                        Style::new().add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Span::styled(row.platform, DIM)),
                    Cell::from(Span::styled(device_short(row.device), DIM)),
                ]
                .into_iter()
                .chain(
                    Layer::PROTOCOLS
                        .iter()
                        .zip(row.protocols)
                        .map(|(layer, present)| {
                            Cell::from(if present {
                                Span::styled("●", Style::new().fg(layer.color()))
                            } else {
                                Span::styled("·", DIM)
                            })
                        }),
                )
                .chain([Cell::from(
                    Line::from(Span::styled(row.weight.clone(), NUMBER)).right_aligned(),
                )]),
            )
        });
        let widths = [
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(4),
        ];
        let focused = self.focus == Focus::Profiles;
        let mut state = TableState::default()
            .with_selected((!self.visible.is_empty()).then_some(self.selected));
        frame.render_stateful_widget(
            Table::new(rows, widths)
                .header(header)
                .column_spacing(1)
                .block(pane("Profiles", focused))
                .row_highlight_style(if focused {
                    SELECTED
                } else {
                    SELECTED_UNFOCUSED
                }),
            area,
            &mut state,
        );
    }

    fn draw_details(&self, frame: &mut Frame<'_>, area: Rect) {
        let Some(row) = self
            .visible
            .get(self.selected)
            .map(|index| &self.rows[*index])
        else {
            frame.render_widget(
                Paragraph::new("No matching profiles.").block(pane("Profile", false)),
                area,
            );
            return;
        };
        let block = Block::bordered().title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                row.client.clone(),
                Style::new()
                    .fg(client_color(&row.client))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", row.version),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("· {} {} ", row.platform, row.device), DIM),
        ]));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let [identity, tabs, body] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(inner);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    row.user_agent.clone(),
                    Style::new().fg(Color::White),
                )),
                Line::from(vec![
                    Span::styled(format!("{} observed", row.weight), NUMBER),
                    Span::styled(
                        row.freshness.as_ref().map_or_else(
                            || " · legacy capture, history unknown".to_owned(),
                            |freshness| format!(" · {freshness}"),
                        ),
                        DIM,
                    ),
                ]),
            ])
            .wrap(Wrap { trim: true }),
            identity,
        );
        let view = self.view.as_ref();
        frame.render_widget(
            Tabs::new(Layer::ALL.iter().enumerate().map(|(index, layer)| {
                let count = view.map_or(0, |view| view.layers[index].len());
                let style = if index == 0 || count > 0 {
                    Style::new().fg(layer.color())
                } else {
                    DIM
                };
                Line::from(vec![
                    Span::styled(format!("{} {}", index + 1, layer.tab()), style),
                    Span::styled(
                        if index == 0 {
                            String::new()
                        } else {
                            format!(" {count}")
                        },
                        DIM,
                    ),
                ])
            }))
            .select(self.layer)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD))
            .divider(Span::styled("│", DIM)),
            tabs,
        );
        if self.layer() == Layer::Overview {
            frame.render_widget(
                Paragraph::new(view.map_or_else(Vec::new, |view| view.overview.clone()))
                    .wrap(Wrap { trim: false })
                    .scroll((self.scroll, 0)),
                body,
            );
            return;
        }
        let [scopes, capture] = if body.width >= 90 {
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body)
        } else {
            Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)]).areas(body)
        };
        self.draw_scopes(frame, scopes);
        self.draw_capture(frame, capture);
    }

    fn draw_scopes(&self, frame: &mut Frame<'_>, area: Rect) {
        let color = self.layer().color();
        let focused = self.focus == Focus::Scopes;
        let items = self.scopes().iter().map(|(index, label)| {
            let variants = self
                .visible
                .get(self.selected)
                .and_then(|row| self.rows[*row].profile.captured.as_ref())
                .and_then(|captured| captured.scopes.get(*index))
                .map_or(0, |scope| scope.observations.variants.len());
            let mut first = vec![
                Span::styled(
                    label.flow.clone(),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(label.capture.clone(), KEY),
                Span::styled(format!(" ×{variants} "), DIM),
                Span::styled(label.shape.clone(), DIM),
            ];
            if !label.detail.is_empty() {
                first.push(Span::styled(format!("  {}", label.detail), DIM));
            }
            ListItem::new(Line::from(first))
        });
        let mut state =
            ListState::default().with_selected((!self.scopes().is_empty()).then_some(self.scope));
        frame.render_stateful_widget(
            List::new(items)
                .block(pane(&format!("{} scopes", self.layer().title()), focused))
                .highlight_style(if focused {
                    SELECTED
                } else {
                    SELECTED_UNFOCUSED
                }),
            area,
            &mut state,
        );
    }

    fn draw_capture(&self, frame: &mut Frame<'_>, area: Rect) {
        let Some(scope) = self.selected_scope() else {
            frame.render_widget(
                Paragraph::new(Span::styled("No scopes observed for this layer.", DIM))
                    .block(pane("Capture", false)),
                area,
            );
            return;
        };
        let variants = &scope.observations.variants;
        let Some(variant) = variants.get(self.variant) else {
            frame.render_widget(
                Paragraph::new(Span::styled("No retained variants.", DIM))
                    .block(pane("Capture", false)),
                area,
            );
            return;
        };
        let (weight, share) = variant_weight(&variant.weight, scope.observations.counts.total);
        let mut lines = vec![Line::from(vec![
            Span::styled(bar(share, 20), Style::new().fg(self.layer().color())),
            Span::styled(format!(" {:>3.0}%  ", share * 100.0), NUMBER),
            Span::styled(weight, DIM),
        ])];
        if scope.observations.counts.losses.oversize + scope.observations.counts.losses.retention
            > 0
        {
            lines.push(Line::from(Span::styled(
                format!(
                    "{} oversized and {} retention losses not shown",
                    scope.observations.counts.losses.oversize,
                    scope.observations.counts.losses.retention
                ),
                DIM,
            )));
        }
        lines.push(Line::default());
        let Lines(capture) = render::capture(&variant.value);
        lines.extend(capture);
        let title = Line::from(vec![
            Span::raw(" "),
            Span::styled(
                self.scopes()
                    .get(self.scope)
                    .map_or_else(String::new, |(_, label)| label.capture.clone()),
                KEY,
            ),
            Span::styled(
                format!(" · variant {}/{} ", self.variant + 1, variants.len()),
                NUMBER,
            ),
            Span::styled("[ ] ", DIM),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title(title))
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            area,
        );
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

fn profile_view(index: usize, row: &Row) -> ProfileView {
    let layers = Layer::ALL
        .iter()
        .map(|layer| match &row.profile.captured {
            Some(captured) => layer
                .scopes(captured)
                .into_iter()
                .map(|scope| (scope, ScopeLabel::new(&captured.scopes[scope])))
                .collect(),
            None => Vec::new(),
        })
        .collect::<Vec<Vec<_>>>();
    let mut overview = Vec::new();
    match &row.profile.captured {
        None => overview.push(Line::from(Span::styled(
            "Legacy capture: original sample counts and freshness are unknown.",
            DIM,
        ))),
        Some(captured) => {
            overview.push(Line::from(Span::styled("Layers", SECTION)));
            for (position, layer) in Layer::ALL.iter().enumerate().skip(1) {
                let scopes = &layers[position];
                if scopes.is_empty() {
                    continue;
                }
                let variants: usize = scopes
                    .iter()
                    .map(|(scope, _)| captured.scopes[*scope].observations.variants.len())
                    .sum();
                let mut flows: Vec<&str> = scopes
                    .iter()
                    .filter(|(_, label)| label.flow != "connection")
                    .map(|(_, label)| label.flow.as_str())
                    .collect();
                flows.dedup();
                overview.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<9}", layer.title()),
                        Style::new().fg(layer.color()).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:>3} scopes {:>5} variants", scopes.len(), variants),
                        NUMBER,
                    ),
                    Span::styled(
                        if flows.is_empty() {
                            String::new()
                        } else {
                            format!("  {}", flows.join(" · "))
                        },
                        DIM,
                    ),
                ]));
            }
        }
    }
    let fingerprints = [
        ("TLS/TCP JA4", row.profile.recorded_tcp_client_hellos()),
        ("TLS/QUIC JA4", row.profile.recorded_quic_client_hellos()),
    ];
    for (title, hellos) in fingerprints {
        let mut values: Vec<String> = hellos
            .iter()
            .filter_map(|hello| Ja4::compute_from_client_hello(hello).ok())
            .map(|ja4| ja4.to_string())
            .collect();
        values.sort();
        values.dedup();
        if !values.is_empty() {
            overview.push(Line::default());
            overview.push(Line::from(Span::styled(title, SECTION)));
            overview.extend(
                values
                    .into_iter()
                    .map(|value| Line::from(Span::styled(format!("  {value}"), NUMBER))),
            );
        }
    }
    let mut ja4h: Vec<String> = row
        .profile
        .recorded_request_headers()
        .into_iter()
        .filter_map(|recorded| {
            Ja4H::compute(HttpRequestInput {
                header_map: recorded.headers,
                http_method: recorded.method,
                version: recorded.version,
            })
            .ok()
        })
        .map(|ja4h| ja4h.to_string())
        .collect();
    ja4h.sort();
    ja4h.dedup();
    if !ja4h.is_empty() {
        overview.push(Line::default());
        overview.push(Line::from(Span::styled(
            format!("HTTP JA4H ({})", ja4h.len()),
            SECTION,
        )));
        overview.extend(
            ja4h.into_iter()
                .map(|value| Line::from(Span::styled(format!("  {value}"), NUMBER))),
        );
    }
    ProfileView {
        row: index,
        layers,
        overview,
    }
}

fn pane(title: &str, focused: bool) -> Block<'static> {
    let block = Block::bordered().title(format!(" {title} "));
    if focused {
        block.border_style(FOCUSED_BORDER)
    } else {
        block.border_style(DIM)
    }
}

fn bar(share: f64, width: usize) -> String {
    let filled = ((share * width as f64).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn client_color(client: &str) -> Color {
    let client = client.to_ascii_lowercase();
    if client.contains("chrom") || client.contains("edge") {
        Color::LightBlue
    } else if client.contains("firefox") {
        Color::LightRed
    } else if client.contains("safari") {
        Color::LightCyan
    } else {
        Color::White
    }
}

fn device_short(device: &str) -> &str {
    match device {
        "Desktop" => "dsk",
        "Mobile" => "mob",
        "Tablet" => "tab",
        other => other,
    }
}

fn hints(keys: &[(&'static str, &'static str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, action) in keys {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::new().fg(Color::Black).bg(Color::DarkGray),
        ));
        spans.push(Span::styled(format!(" {action}  "), DIM));
    }
    Line::from(spans)
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let [_, middle, _] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(24),
        Constraint::Min(0),
    ])
    .areas(area);
    let [_, area, _] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(72),
        Constraint::Min(0),
    ])
    .areas(middle);
    let key = |key: &'static str, action: &'static str| {
        Line::from(vec![
            Span::styled(format!("  {key:<14}"), KEY),
            Span::raw(action),
        ])
    };
    let mut lines = vec![
        Line::from(Span::styled("Navigation", SECTION)),
        key("↑↓ j k", "select a profile or scope"),
        key("Tab Enter", "switch focus between profiles and scopes"),
        key("←→ h l 1-8", "switch the layer of the selected profile"),
        key("[ ]", "previous or next retained variant"),
        key("PgUp PgDn", "scroll the capture"),
        key(
            "/ Esc",
            "filter on client, version, platform, UA or H3, QTLS…",
        ),
        key("q Ctrl-C", "quit"),
        Line::default(),
        Line::from(Span::styled("Layers", SECTION)),
    ];
    lines.extend(Layer::PROTOCOLS.iter().map(|layer| {
        Line::from(vec![
            Span::styled(
                format!("  {:<6}", layer.chip()),
                Style::new().fg(layer.color()).add_modifier(Modifier::BOLD),
            ),
            Span::raw(layer.title()),
        ])
    }));
    lines.extend([
        Line::default(),
        Line::from(Span::styled("Values", SECTION)),
        Line::from(vec![
            Span::styled(
                "  ‹magenta›",
                Style::new()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::ITALIC),
            ),
            Span::raw("  supplied per request or connection, never replayed"),
        ]),
        Line::from(vec![
            Span::styled("  GREASE", DIM),
            Span::raw("  randomized placeholder values"),
        ]),
        Line::from(Span::styled(
            "  Protocols indicate observed data, not replay readiness.",
            DIM,
        )),
    ]);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(pane("Help · ? or Esc closes", true)),
        area,
    );
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

#[cfg(test)]
mod tests {
    use super::{super::display::sort_rows, super::source, *};
    use rama::ua::profile::model::{identity::ProfileKey, ua::UserAgentProfile};
    use ratatui::{Terminal, backend::TestBackend};

    fn screen(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn viewer_filter_selection_and_resize_handle_empty_results() {
        let rows = ["alpha-library", "beta-library"]
            .map(|name| Row::from_profile(UserAgentProfile::new(ProfileKey::new(name))).unwrap())
            .into_iter()
            .collect();
        let mut app = App::new(rows, "test input".to_owned());
        assert!(!app.key(key(KeyCode::Down)));
        assert_eq!(app.selected, 1);
        app.key(key(KeyCode::Char('/')));
        for ch in "beta".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        assert_eq!(app.visible, [1]);
        app.key(key(KeyCode::Enter));
        let text = screen(&app, 120, 24);
        assert!(text.contains("beta-library"));
        assert!(text.contains("Overview"));
        app.filter = "no such profile".to_owned();
        app.filter();
        for code in [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::End,
            KeyCode::PageDown,
            KeyCode::Right,
            KeyCode::Char(']'),
        ] {
            app.key(key(code));
        }
        assert!(app.visible.is_empty());
        for (width, height) in [(1, 1), (8, 3), (60, 12), (120, 24)] {
            screen(&app, width, height);
        }
        app.key(key(KeyCode::Esc));
        assert_eq!(app.visible, [0, 1]);
        assert_eq!(app.scroll, 0);
        app.key(key(KeyCode::Char('?')));
        assert!(screen(&app, 120, 30).contains("Navigation"));
        app.key(key(KeyCode::Esc));
        assert!(!app.help);
        assert!(app.key(key(KeyCode::Char('q'))));
    }

    #[test]
    fn every_layer_scope_and_variant_of_embedded_profiles_renders() {
        let mut rows = source::embedded().unwrap().rows;
        sort_rows(&mut rows);
        let mut app = App::new(rows, "embedded profiles".to_owned());
        let with_h3 = app
            .visible
            .iter()
            .position(|index| app.rows[*index].protocols[2])
            .unwrap();
        app.selected = with_h3;
        app.sync();
        app.key(key(KeyCode::Enter));
        assert_eq!(app.focus, Focus::Scopes);
        for layer in 0..Layer::ALL.len() {
            app.set_layer(layer);
            let text = screen(&app, 180, 50);
            assert!(!text.contains('\u{1b}'));
            for scope in 0..app.scopes().len() {
                app.scope = scope;
                app.variant = 0;
                for _ in 0..app.variants().min(3) {
                    let text = screen(&app, 180, 50);
                    assert!(!text.contains("undecodable"), "{text}");
                    app.key(key(KeyCode::Char(']')));
                }
            }
        }
        app.set_layer(1);
        let text = screen(&app, 180, 50);
        assert!(text.contains("cipher suites"));
    }
}
