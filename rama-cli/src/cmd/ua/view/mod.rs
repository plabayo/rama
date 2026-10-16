//! A bounded, read-only overview of captured user-agent profiles.

mod inspect;

use std::{
    fmt::Write as _,
    fs::File,
    io::{self, IsTerminal as _, Read as _, Write as _},
    path::PathBuf,
};

use clap::Args;
use jiff::{Timestamp, tz::TimeZone};
use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    ua::profile::{
        analysis::profile::ProfileAnalysisLimits,
        evidence::counts::ObservationWeight,
        format::{
            archive::{ProfileArchiveLimits, load_profile_archive_snapshot},
            input::try_load_profiles_json,
        },
        model::{identity::FlowKey, ua::UserAgentProfile},
    },
    utils::octets::{kib, mib},
};
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::{cmd::serve::fp::CountedProfileSource, utils::terminal::display_text};

#[derive(Debug, Args)]
pub(super) struct ViewCommand {
    /// Profile JSON file; omit to read RAMA_FP_DATABASE_URL.
    path: Option<PathBuf>,
    /// Read the authorized partition, including authorized archive files.
    #[arg(long)]
    authorized: bool,
    /// Database freshness window, including the current partial UTC day.
    #[arg(long, default_value_t = 14)]
    days: u32,
    /// Print a text summary; also used automatically outside a terminal.
    #[arg(short = 's', long)]
    summary: bool,
    /// Print validated, decoded retained captures as JSON for an archive file.
    #[arg(long, requires = "path", conflicts_with = "summary")]
    json: bool,
}

#[derive(Debug)]
struct Row {
    label: String,
    details: String,
}

impl Row {
    fn from_profile(profile: &UserAgentProfile) -> Result<Self, BoxError> {
        let capability = profile.capabilities();
        let protocols = [
            (capability.h1, "H1"),
            (capability.h2, "H2"),
            (capability.h3, "H3"),
            (capability.tls_tcp, "TLS/TCP"),
            (capability.tls_quic, "TLS/QUIC"),
            (capability.quic, "QUIC"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect::<Vec<_>>()
        .join(", ");
        let protocols = if protocols.is_empty() {
            "none observed"
        } else {
            &protocols
        };
        let weight = match profile.observation_weight()? {
            ObservationWeight::Exact(count) => format!("{count} exact"),
            ObservationWeight::UnknownHistory { observed, .. } => {
                format!("{observed} retained; earlier history unknown")
            }
            ObservationWeight::LowerBound { observed, .. } => format!("at least {observed}"),
        };
        let client = display_text(&profile.key.client);
        let version = display_text(profile.key.version.as_deref().unwrap_or("unknown"));
        let mut details = format!(
            "Client: {client}\nVersion: {version}\nPlatform: {}\nDevice: {}\nProtocols: {protocols}\nObservations: {weight}\nUser-Agent: {}\n",
            profile
                .key
                .platform
                .map_or("unknown", |value| value.as_str()),
            profile.key.device.map_or("unknown", |value| value.as_str()),
            display_text(profile.ua_str().unwrap_or("not recorded")),
        );
        if let Some(captured) = &profile.captured {
            let through = Timestamp::from_second(i64::from(captured.current_day) * 86_400)?
                .to_zoned(TimeZone::UTC)
                .date();
            writeln!(
                details,
                "\nFreshness: {} UTC day buckets through {through}\nClassifier revision: {}\nScopes: {}",
                captured.horizon,
                captured.classifier_revision,
                captured.scopes.len()
            )?;
            for scope in &captured.scopes {
                let flow = match &scope.flow {
                    Some(FlowKey::Http {
                        version,
                        method,
                        initiator,
                        ..
                    }) => {
                        format!("{version:?} {method} {initiator:?}")
                    }
                    Some(FlowKey::Other {
                        protocol,
                        operation,
                    }) => {
                        format!("{} {}", display_text(protocol), display_text(operation))
                    }
                    None => "connection".to_owned(),
                };
                let observations = &scope.observations;
                let counts = &observations.counts;
                writeln!(
                    details,
                    "\n{flow} / {:?}\n  {} observations, {} literal values, {} retained samples\n  {} unassigned; {} oversized, {} retention losses; history {}\n  {} order analyses, {} numeric distributions",
                    observations.domain,
                    counts.total,
                    counts.values.len(),
                    observations.retained_samples,
                    counts.untracked,
                    counts.losses.oversize,
                    counts.losses.retention,
                    if counts.losses.history_known {
                        "known"
                    } else {
                        "unknown"
                    },
                    observations.orders.len(),
                    observations.numeric.len()
                )?;
                if details.len() > kib(64) {
                    details.push_str("\nFurther scope details omitted from this overview.\n");
                    break;
                }
            }
        } else {
            details
                .push_str("\nLegacy capture: original sample counts and freshness are unknown.\n");
        }
        Ok(Self {
            label: format!("{client} {version}  [{protocols}]  {weight}"),
            details,
        })
    }
}

fn push_row(rows: &mut Vec<Row>, remaining: &mut usize, row: Row) -> Result<(), BoxError> {
    *remaining = remaining
        .checked_sub(row.label.len())
        .and_then(|bytes| bytes.checked_sub(row.details.len()))
        .ok_or_else(|| BoxError::from_static_str("profile viewer memory limit exceeded"))?;
    rows.push(row);
    Ok(())
}

fn read_profile_file(path: PathBuf) -> Result<Vec<u8>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limits.bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limits.bytes {
        return Err(BoxError::from_static_str(
            "profile input byte limit exceeded",
        ));
    }
    Ok(bytes)
}

fn file_rows(path: PathBuf, authorized: bool) -> Result<Vec<Row>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let bytes = read_profile_file(path)?;
    let profiles = if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
        load_profile_archive_snapshot(&bytes, authorized, limits)?
            .into_vec()
            .into_iter()
            .map(|entry| UserAgentProfile::from_captured(entry.analysis))
            .collect()
    } else {
        try_load_profiles_json(&bytes)?
    };
    let mut rows = Vec::new();
    let mut remaining = mib(64);
    for profile in profiles {
        push_row(&mut rows, &mut remaining, Row::from_profile(&profile)?)?;
    }
    Ok(rows)
}

pub(super) async fn run(command: ViewCommand) -> Result<(), BoxError> {
    if command.json {
        let path = command
            .path
            .ok_or_else(|| BoxError::from_static_str("JSON inspection requires an archive file"))?;
        let bytes = tokio::task::spawn_blocking(move || {
            inspect::archive_json(&read_profile_file(path)?, command.authorized)
        })
        .await??;
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    let mut source_label = command.path.as_ref().map_or_else(
        || {
            format!(
                "fingerprint database / {} / {} days",
                if command.authorized {
                    "authorized"
                } else {
                    "public"
                },
                command.days
            )
        },
        |path| display_text(&path.to_string_lossy()),
    );
    let rows = if let Some(path) = command.path {
        tokio::task::spawn_blocking(move || file_rows(path, command.authorized)).await??
    } else {
        let mut source = CountedProfileSource::open(
            command.authorized,
            command.days,
            ProfileArchiveLimits::default().profiles,
        )
        .await?;
        let mut rows = Vec::new();
        let mut remaining = mib(64);
        let day = source.day();
        while let Some(entry) = source.next().await? {
            let row = tokio::task::spawn_blocking(move || {
                let entry = entry.analyze(
                    command.authorized,
                    day,
                    command.days,
                    ProfileAnalysisLimits::default(),
                )?;
                Row::from_profile(&UserAgentProfile::from_captured(entry.analysis))
            })
            .await??;
            push_row(&mut rows, &mut remaining, row)?;
        }
        if source.skipped() > 0 || source.limited() {
            write!(
                source_label,
                " / {} over-limit profiles skipped{}",
                source.skipped(),
                if source.limited() {
                    " / read budget reached"
                } else {
                    ""
                }
            )?;
        }
        rows
    };
    if command.summary || !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        let mut output = io::stdout().lock();
        writeln!(output, "{} profiles — {source_label}", rows.len())?;
        for row in rows {
            writeln!(output, "{}", row.label)?;
        }
        return Ok(());
    }
    tokio::task::spawn_blocking(move || App::new(rows, source_label).run()).await?
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
mod tests;
