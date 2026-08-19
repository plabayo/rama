use std::{
    env,
    io::{self, BufRead, IsTerminal as _, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use clap::{Args, ValueEnum};
use rama::{
    dns::client::EmptyDnsResolver,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    js::pac::{PacDirectives, PacEnv, PacLocalAddresses, PacResolver, PacUrlSanitize},
    net::uri::Uri,
};
use ratatui::{
    crossterm::{
        cursor::{MoveLeft, MoveTo, MoveToColumn},
        event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
        queue,
        terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
    },
    text::Span,
};
use serde::Serialize;

use super::{source::LoadedSource, warm_up_javascript_engine};
use crate::cmd::uri::parse_user_uri;

const REPL_PROMPT: &str = "pac> ";
const REPL_HISTORY_SIZE: usize = 1_000;
const LOADING_DELAY: Duration = Duration::from_millis(150);
const LOADING_FRAME_INTERVAL: Duration = Duration::from_millis(125);
const LOADING_COMPILING: u8 = 0;
const LOADING_SCRIPT: u8 = 1;
const LOADING_SUCCEEDED: u8 = 2;
const LOADING_STOPPED: u8 = 3;

#[derive(Debug, Args)]
pub(super) struct EvalCommand {
    /// PAC source followed by URIs. With --file/--source/--stdin, every
    /// positional value is a URI.
    #[arg(value_name = "PAC_OR_URI")]
    inputs: Vec<String>,

    /// Read PAC source from this file.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["source", "stdin"])]
    file: Option<PathBuf>,

    /// Use this inline PAC source.
    #[arg(long, value_name = "JAVASCRIPT", conflicts_with = "stdin")]
    source: Option<String>,

    /// Read PAC source from stdin, even when stdin is a terminal.
    #[arg(long)]
    stdin: bool,

    /// Batch output format.
    #[arg(long, value_enum, default_value_t)]
    format: OutputFormat,

    /// Stop batch evaluation after the first failed URI.
    #[arg(long)]
    fail_fast: bool,

    /// Build a fresh JavaScript realm for every URI.
    #[arg(long)]
    fresh: bool,

    /// Disable DNS and disclose no local interface addresses to the PAC script.
    #[arg(long)]
    offline: bool,

    /// How much of each URI the PAC script may see.
    #[arg(long, value_enum, default_value_t)]
    sanitize: SanitizeArg,

    /// JavaScript execution limit, such as `500ms`, `2s`, or `1m`.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum SanitizeArg {
    #[default]
    HttpsOnly,
    All,
    None,
}

impl From<SanitizeArg> for PacUrlSanitize {
    fn from(value: SanitizeArg) -> Self {
        match value {
            SanitizeArg::HttpsOnly => Self::HttpsOnly,
            SanitizeArg::All => Self::All,
            SanitizeArg::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EvalSettings {
    sanitize: PacUrlSanitize,
    execution_time_limit: Option<Duration>,
    offline: bool,
    fresh: bool,
}

struct EvalSession {
    source: LoadedSource,
    settings: EvalSettings,
    resolver: PacResolver,
}

struct EvalResult {
    uri: Uri,
    directives: PacDirectives,
}

impl EvalSession {
    fn new(source: LoadedSource, settings: EvalSettings) -> Result<Self, BoxError> {
        let resolver = build_resolver(source.as_str(), settings)?;
        Ok(Self {
            source,
            settings,
            resolver,
        })
    }

    async fn evaluate(&self, input: &str) -> Result<EvalResult, BoxError> {
        let uri = parse_user_uri(input)
            .context("prepare URI for PAC evaluation")
            .with_context_str_field("uri", || input.to_owned())?;
        if uri.host().is_none() {
            return Err(
                BoxError::from_static_str("PAC evaluation requires a URI with a host")
                    .context_str_field("uri", input.to_owned()),
            );
        }

        let directives = if self.settings.fresh {
            build_resolver(self.source.as_str(), self.settings)?
                .find_proxy(&uri)
                .await?
        } else {
            self.resolver.find_proxy(&uri).await?
        };
        Ok(EvalResult { uri, directives })
    }

    fn reset(&mut self) -> Result<(), BoxError> {
        let resolver = build_resolver(self.source.as_str(), self.settings)?;
        self.resolver = resolver;
        Ok(())
    }

    fn reload(&mut self) -> Result<(), BoxError> {
        let mut source = self.source.clone();
        source.reload()?;
        self.replace(source, self.settings)
    }

    fn load_file(&mut self, path: PathBuf) -> Result<(), BoxError> {
        let mut source = self.source.clone();
        source.replace_with_file(path)?;
        self.replace(source, self.settings)
    }

    fn set_sanitize(&mut self, sanitize: PacUrlSanitize) -> Result<(), BoxError> {
        let mut settings = self.settings;
        settings.sanitize = sanitize;
        self.replace(self.source.clone(), settings)
    }

    fn replace(&mut self, source: LoadedSource, settings: EvalSettings) -> Result<(), BoxError> {
        let resolver = build_resolver(source.as_str(), settings)?;
        self.source = source;
        self.settings = settings;
        self.resolver = resolver;
        Ok(())
    }
}

fn build_resolver(source: &str, settings: EvalSettings) -> Result<PacResolver, BoxError> {
    let mut env = PacEnv::default();
    if settings.offline {
        env = env.with_dns_resolver(EmptyDnsResolver::new());
        env.set_local_addresses(PacLocalAddresses::Loopback);
    }

    let mut builder = PacResolver::builder()
        .with_env(env)
        .with_sanitize(settings.sanitize);
    if let Some(limit) = settings.execution_time_limit {
        builder.set_execution_time_limit(limit);
    }
    builder.build_static(source)
}

pub(super) async fn run(config: EvalCommand, verbose: bool) -> Result<(), BoxError> {
    let stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let explicit_source =
        has_explicit_source(config.file.is_some(), config.source.is_some(), config.stdin);
    let (pac, uris) = split_inputs(config.inputs, explicit_source);
    if missing_terminal_source(
        stdin_is_terminal,
        [
            pac.is_some(),
            config.file.is_some(),
            config.source.is_some(),
            config.stdin,
        ],
    ) {
        return Err(BoxError::from_static_str(
            "PAC source is required; pass a file, inline source, `-`, or --stdin",
        ));
    }

    let mut stdin = stdin.lock();
    let source = LoadedSource::load(pac, config.file, config.source, config.stdin, &mut stdin)?;
    let source_from_stdin = source.came_from_stdin();
    let settings = EvalSettings {
        sanitize: config.sanitize.into(),
        execution_time_limit: config.timeout,
        offline: config.offline,
        fresh: config.fresh,
    };

    let mode = select_mode(stdin_is_terminal, source_from_stdin, has_uri_inputs(&uris));
    match mode {
        EvalMode::Batch => {
            let mut inputs = uris;
            append_piped_uris(
                &mut inputs,
                source_from_stdin,
                stdin_is_terminal,
                &mut stdin,
            )?;
            if inputs.is_empty() {
                return Err(BoxError::from_static_str(
                    "no URI was supplied for non-interactive PAC evaluation",
                ));
            }
            let session = build_session_with_status(source, settings, verbose)?;
            let outcomes = evaluate_batch(&session, inputs, config.fail_fast).await;
            let failures = outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count();
            write_outcomes(io::stdout().lock(), &outcomes, config.format)?;
            if failures > 0 {
                return Err(
                    BoxError::from_static_str("one or more PAC evaluations failed")
                        .context_field("failures", failures),
                );
            }
            Ok(())
        }
        EvalMode::Repl => {
            let session = build_session_with_status(source, settings, verbose)?;
            let terminal = terminal_prompt::Terminal::open().context(
                "open controlling terminal for PAC REPL; provide URI arguments for batch mode",
            )?;
            let mut terminal = ReplLineEditor::new(terminal);
            run_repl(&mut terminal, session).await
        }
    }
}

fn build_session_with_status(
    source: LoadedSource,
    settings: EvalSettings,
    verbose: bool,
) -> Result<EvalSession, BoxError> {
    let quiet_logging = !verbose
        && env::var_os("RUST_LOG").is_none()
        && env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_none();
    let indicator = LoadingIndicator::start(loading_animation_enabled(
        io::stderr().is_terminal(),
        quiet_logging,
        !matches!(env::var("TERM").as_deref(), Ok("dumb")),
    ));
    if let Err(error) = warm_up_javascript_engine() {
        indicator.finish(false);
        return Err(error);
    }
    indicator.set_stage(LOADING_SCRIPT);
    let result = EvalSession::new(source, settings);
    indicator.finish(result.is_ok());
    result
}

const fn loading_animation_enabled(
    stderr_is_terminal: bool,
    quiet_logging: bool,
    capable_terminal: bool,
) -> bool {
    stderr_is_terminal && quiet_logging && capable_terminal
}

struct LoadingIndicator {
    state: Arc<AtomicU8>,
    handle: Option<JoinHandle<()>>,
}

impl LoadingIndicator {
    fn start(enabled: bool) -> Self {
        let state = Arc::new(AtomicU8::new(LOADING_COMPILING));
        let handle = enabled.then(|| {
            let state = Arc::clone(&state);
            std::thread::Builder::new()
                .name("rama-pac-loading".to_owned())
                .spawn(move || drop(animate_loading(state.as_ref())))
        });
        let handle = handle.and_then(Result::ok);
        Self { state, handle }
    }

    fn set_stage(&self, stage: u8) {
        self.state.store(stage, Ordering::Release);
    }

    fn finish(mut self, succeeded: bool) {
        self.stop(if succeeded {
            LOADING_SUCCEEDED
        } else {
            LOADING_STOPPED
        });
    }

    fn stop(&mut self, state: u8) {
        loop {
            let current = self.state.load(Ordering::Acquire);
            if current >= LOADING_SUCCEEDED {
                return;
            }
            if self
                .state
                .compare_exchange(current, state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            drop(handle.join());
        }
    }
}

impl Drop for LoadingIndicator {
    fn drop(&mut self) {
        self.stop(LOADING_STOPPED);
    }
}

fn animate_loading(state: &AtomicU8) -> io::Result<()> {
    let started = Instant::now();
    std::thread::park_timeout(LOADING_DELAY);
    if state.load(Ordering::Acquire) >= LOADING_SUCCEEDED {
        return Ok(());
    }

    let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut frame_index = 0;
    while state.load(Ordering::Acquire) < LOADING_SUCCEEDED {
        let frame = frames[frame_index];
        frame_index = (frame_index + 1) % frames.len();
        {
            let mut stderr = io::stderr().lock();
            write_loading_frame(
                &mut stderr,
                frame,
                state.load(Ordering::Acquire),
                started.elapsed(),
            )?;
            stderr.flush()?;
        }
        std::thread::park_timeout(LOADING_FRAME_INTERVAL);
    }

    let mut stderr = io::stderr().lock();
    queue!(stderr, MoveToColumn(0), Clear(ClearType::CurrentLine))?;
    if state.load(Ordering::Acquire) == LOADING_SUCCEEDED {
        writeln!(
            stderr,
            "✓ PAC evaluator ready            {:>5.1}s",
            started.elapsed().as_secs_f64()
        )?;
    }
    stderr.flush()
}

fn write_loading_frame(
    writer: &mut impl Write,
    frame: char,
    stage: u8,
    elapsed: Duration,
) -> io::Result<()> {
    let label = match stage {
        LOADING_SCRIPT => "Loading PAC script",
        _ => "Compiling JavaScript engine",
    };
    queue!(writer, MoveToColumn(0), Clear(ClearType::CurrentLine))?;
    write!(
        writer,
        "{frame} {label:<30} {:>5.1}s",
        elapsed.as_secs_f64()
    )
}

fn has_explicit_source(file: bool, inline: bool, stdin: bool) -> bool {
    file || inline || stdin
}

fn missing_terminal_source(stdin_is_terminal: bool, sources: [bool; 4]) -> bool {
    stdin_is_terminal && !sources.into_iter().any(std::convert::identity)
}

fn has_uri_inputs(inputs: &[String]) -> bool {
    !inputs.is_empty()
}

fn split_inputs(mut inputs: Vec<String>, explicit_source: bool) -> (Option<String>, Vec<String>) {
    if explicit_source || inputs.is_empty() {
        return (None, inputs);
    }
    let uris = inputs.split_off(1);
    (inputs.pop(), uris)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvalMode {
    Batch,
    Repl,
}

fn select_mode(stdin_is_terminal: bool, source_from_stdin: bool, has_uris: bool) -> EvalMode {
    if has_uris || (!stdin_is_terminal && !source_from_stdin) {
        EvalMode::Batch
    } else {
        EvalMode::Repl
    }
}

fn read_uri_lines(reader: &mut impl BufRead) -> Result<Vec<String>, BoxError> {
    reader
        .lines()
        .map(|line| line.context("read URI from stdin"))
        .filter_map(|line| match line {
            Ok(line) if line.trim().is_empty() => None,
            Ok(line) => Some(Ok(line.trim().to_owned())),
            Err(err) => Some(Err(err)),
        })
        .collect()
}

fn append_piped_uris(
    inputs: &mut Vec<String>,
    source_from_stdin: bool,
    stdin_is_terminal: bool,
    reader: &mut impl BufRead,
) -> Result<(), BoxError> {
    if !source_from_stdin && !stdin_is_terminal {
        inputs.extend(read_uri_lines(reader)?);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct EvalOutcome {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    directives: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn evaluate_batch(
    session: &EvalSession,
    inputs: Vec<String>,
    fail_fast: bool,
) -> Vec<EvalOutcome> {
    let mut outcomes = Vec::with_capacity(inputs.len());
    for uri in inputs {
        let outcome = match session.evaluate(&uri).await {
            Ok(result) => EvalOutcome {
                uri: result.uri.to_string(),
                directives: Some(result.directives.to_string()),
                error: None,
            },
            Err(error) => EvalOutcome {
                uri,
                directives: None,
                error: Some(error.to_string()),
            },
        };
        let failed = outcome.error.is_some();
        outcomes.push(outcome);
        if failed && fail_fast {
            break;
        }
    }
    outcomes
}

fn write_outcomes(
    mut writer: impl Write,
    outcomes: &[EvalOutcome],
    format: OutputFormat,
) -> Result<(), BoxError> {
    match format {
        OutputFormat::Text => {
            for outcome in outcomes {
                match (&outcome.directives, &outcome.error) {
                    (Some(directives), None) => {
                        writeln!(writer, "{}\t{directives}", outcome.uri)
                            .context("write PAC evaluation result")?;
                    }
                    (None, Some(error)) => {
                        writeln!(writer, "{}\tERROR\t{error}", outcome.uri)
                            .context("write PAC evaluation error")?;
                    }
                    _ => {
                        return Err(BoxError::from_static_str(
                            "invalid internal PAC evaluation outcome",
                        ));
                    }
                }
            }
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut writer, outcomes)
                .context("serialize PAC evaluation results")?;
            writeln!(writer).context("finish PAC JSON output")?;
        }
        OutputFormat::Jsonl => {
            for outcome in outcomes {
                serde_json::to_writer(&mut writer, outcome)
                    .context("serialize PAC evaluation result")?;
                writeln!(writer).context("finish PAC JSONL record")?;
            }
        }
    }
    writer.flush().context("flush PAC evaluation results")
}

#[derive(Debug, PartialEq, Eq)]
enum ReplRead {
    Input(String),
    Interrupted,
    Eof,
}

trait ReplIo: Write {
    fn read_repl_line(&mut self) -> io::Result<ReplRead>;
    fn clear_repl_screen(&mut self) -> io::Result<()>;
}

struct ReplLineEditor {
    terminal: terminal_prompt::Terminal,
    history: Vec<String>,
}

impl ReplLineEditor {
    fn new(terminal: terminal_prompt::Terminal) -> Self {
        Self {
            terminal,
            history: Vec::new(),
        }
    }

    fn redraw(&mut self, state: &EditState) -> io::Result<()> {
        queue!(
            self.terminal,
            MoveToColumn(0),
            Clear(ClearType::CurrentLine)
        )?;
        write!(self.terminal, "{REPL_PROMPT}{}", state.text())?;

        let mut suffix_width = state.suffix_width();
        while suffix_width > 0 {
            let step = suffix_width.min(usize::from(u16::MAX));
            queue!(self.terminal, MoveLeft(step as u16))?;
            suffix_width -= step;
        }
        self.terminal.flush()
    }

    fn remember(&mut self, line: &str) {
        if line.is_empty() || self.history.last().is_some_and(|last| last == line) {
            return;
        }
        if self.history.len() == REPL_HISTORY_SIZE {
            self.history.remove(0);
        }
        self.history.push(line.to_owned());
    }
}

impl Write for ReplLineEditor {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.terminal.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.terminal.flush()
    }
}

impl ReplIo for ReplLineEditor {
    fn read_repl_line(&mut self) -> io::Result<ReplRead> {
        let _raw_mode = RawModeGuard::enable()?;
        let mut state = EditState::default();
        write!(self.terminal, "{REPL_PROMPT}")?;
        self.terminal.flush()?;

        loop {
            let action = match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    state.handle_key(key, &self.history)
                }
                Event::Paste(text) => {
                    state.insert(&text);
                    EditAction::Redraw
                }
                _ => EditAction::None,
            };

            match action {
                EditAction::None => {}
                EditAction::Redraw => self.redraw(&state)?,
                EditAction::ClearScreen => {
                    queue!(self.terminal, Clear(ClearType::All), MoveTo(0, 0))?;
                    self.redraw(&state)?;
                }
                EditAction::Submit => {
                    write_raw_line_end(&mut self.terminal)?;
                    let line = state.text();
                    self.remember(&line);
                    return Ok(ReplRead::Input(line));
                }
                EditAction::Interrupted => {
                    write!(self.terminal, "^C")?;
                    write_raw_line_end(&mut self.terminal)?;
                    return Ok(ReplRead::Interrupted);
                }
                EditAction::Eof => {
                    write_raw_line_end(&mut self.terminal)?;
                    return Ok(ReplRead::Eof);
                }
            }
        }
    }

    fn clear_repl_screen(&mut self) -> io::Result<()> {
        queue!(self.terminal, Clear(ClearType::All), MoveTo(0, 0))?;
        self.terminal.flush()
    }
}

fn write_raw_line_end(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(b"\r\n")
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        drop(disable_raw_mode());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditAction {
    None,
    Redraw,
    ClearScreen,
    Submit,
    Interrupted,
    Eof,
}

#[derive(Default)]
struct EditState {
    buffer: Vec<char>,
    cursor: usize,
    history_index: Option<usize>,
    draft: Vec<char>,
}

impl EditState {
    fn text(&self) -> String {
        self.buffer.iter().collect()
    }

    fn suffix_width(&self) -> usize {
        Span::raw(self.buffer[self.cursor..].iter().collect::<String>()).width()
    }

    fn insert(&mut self, text: &str) {
        let chars: Vec<_> = text
            .chars()
            .filter(|character| !matches!(character, '\r' | '\n'))
            .collect();
        self.buffer
            .splice(self.cursor..self.cursor, chars.iter().copied());
        self.cursor += chars.len();
        self.history_index = None;
    }

    fn handle_key(&mut self, key: KeyEvent, history: &[String]) -> EditAction {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if control => EditAction::Interrupted,
            KeyCode::Char('d') if control && self.buffer.is_empty() => EditAction::Eof,
            KeyCode::Char('d') if control => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                    EditAction::Redraw
                } else {
                    EditAction::None
                }
            }
            KeyCode::Char('a') if control => {
                self.cursor = 0;
                EditAction::Redraw
            }
            KeyCode::Char('e') if control => {
                self.cursor = self.buffer.len();
                EditAction::Redraw
            }
            KeyCode::Char('u') if control => {
                self.buffer.drain(..self.cursor);
                self.cursor = 0;
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Char('k') if control => {
                self.buffer.truncate(self.cursor);
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Char('w') if control => {
                let end = self.cursor;
                while self.cursor > 0 && self.buffer[self.cursor - 1].is_whitespace() {
                    self.cursor -= 1;
                }
                while self.cursor > 0 && !self.buffer[self.cursor - 1].is_whitespace() {
                    self.cursor -= 1;
                }
                self.buffer.drain(self.cursor..end);
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Char('l') if control => EditAction::ClearScreen,
            KeyCode::Char(character) if !control && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.buffer.insert(self.cursor, character);
                self.cursor += 1;
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Enter => EditAction::Submit,
            KeyCode::Left if self.cursor > 0 => {
                self.cursor -= 1;
                EditAction::Redraw
            }
            KeyCode::Right if self.cursor < self.buffer.len() => {
                self.cursor += 1;
                EditAction::Redraw
            }
            KeyCode::Home => {
                self.cursor = 0;
                EditAction::Redraw
            }
            KeyCode::End => {
                self.cursor = self.buffer.len();
                EditAction::Redraw
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.buffer.remove(self.cursor);
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Delete if self.cursor < self.buffer.len() => {
                self.buffer.remove(self.cursor);
                self.history_index = None;
                EditAction::Redraw
            }
            KeyCode::Up if !history.is_empty() => {
                let index = if let Some(index) = self.history_index {
                    index.saturating_sub(1)
                } else {
                    self.draft = self.buffer.clone();
                    history.len() - 1
                };
                self.load_history(history, index);
                EditAction::Redraw
            }
            KeyCode::Down => match self.history_index {
                Some(index) if index + 1 < history.len() => {
                    self.load_history(history, index + 1);
                    EditAction::Redraw
                }
                Some(_) => {
                    self.buffer = std::mem::take(&mut self.draft);
                    self.cursor = self.buffer.len();
                    self.history_index = None;
                    EditAction::Redraw
                }
                None => EditAction::None,
            },
            _ => EditAction::None,
        }
    }

    fn load_history(&mut self, history: &[String], index: usize) {
        self.buffer = history[index].chars().collect();
        self.cursor = self.buffer.len();
        self.history_index = Some(index);
    }
}

async fn run_repl<T>(terminal: &mut T, mut session: EvalSession) -> Result<(), BoxError>
where
    T: ReplIo,
{
    writeln!(
        terminal,
        "Loaded {}. Enter a URI, or :help for commands.",
        session.source.description()
    )
    .context("write PAC REPL greeting")?;

    loop {
        let line = match terminal.read_repl_line().context("read PAC REPL input")? {
            ReplRead::Input(line) => line,
            ReplRead::Interrupted => continue,
            ReplRead::Eof => break,
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        match parse_repl_input(input) {
            ReplInput::Evaluate(uri) => match session.evaluate(uri).await {
                Ok(result) => writeln!(terminal, "{}  →  {}", result.uri, result.directives),
                Err(error) => writeln!(terminal, "ERROR: {error}"),
            }
            .context("write PAC REPL result")?,
            ReplInput::Help => write_repl_help(terminal)?,
            ReplInput::Load(path) => match session.load_file(PathBuf::from(path)) {
                Ok(()) => writeln!(terminal, "Loaded {}", session.source.description()),
                Err(error) => writeln!(terminal, "ERROR: {error}"),
            }
            .context("write PAC REPL load result")?,
            ReplInput::Reload => match session.reload() {
                Ok(()) => writeln!(terminal, "Reloaded {}", session.source.description()),
                Err(error) => writeln!(terminal, "ERROR: {error}"),
            }
            .context("write PAC REPL reload result")?,
            ReplInput::Reset => match session.reset() {
                Ok(()) => writeln!(terminal, "PAC realm reset"),
                Err(error) => writeln!(terminal, "ERROR: {error}"),
            }
            .context("write PAC REPL reset result")?,
            ReplInput::Source => {
                writeln!(terminal, "--- {} ---", session.source.description())?;
                writeln!(terminal, "{}", session.source.as_str())?;
                writeln!(terminal, "--- end ---")?;
            }
            ReplInput::Sanitize(sanitize) => match session.set_sanitize(sanitize) {
                Ok(()) => writeln!(terminal, "URI sanitization set to {sanitize:?}"),
                Err(error) => writeln!(terminal, "ERROR: {error}"),
            }
            .context("write PAC REPL sanitization result")?,
            ReplInput::Clear => {
                terminal
                    .clear_repl_screen()
                    .context("clear PAC REPL terminal")?;
            }
            ReplInput::Quit => break,
            ReplInput::Invalid(command) => {
                writeln!(terminal, "Unknown command: {command}. Use :help.")
                    .context("write PAC REPL command error")?;
            }
        }
    }
    terminal.flush().context("flush PAC REPL output")
}

fn write_repl_help(writer: &mut impl Write) -> Result<(), BoxError> {
    writeln!(
        writer,
        ":help                 show this help\n\
         :load PATH            load a PAC file\n\
         :reload               reload a file source, then reset\n\
         :reset                reset the JavaScript realm\n\
         :source               print the current PAC source\n\
         :sanitize MODE        use https-only, all, or none\n\
         :clear                clear the terminal\n\
         :quit                 leave the REPL"
    )
    .context("write PAC REPL help")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplInput<'a> {
    Evaluate(&'a str),
    Help,
    Load(&'a str),
    Reload,
    Reset,
    Source,
    Sanitize(PacUrlSanitize),
    Clear,
    Quit,
    Invalid(&'a str),
}

fn parse_repl_input(input: &str) -> ReplInput<'_> {
    match input {
        ":help" => ReplInput::Help,
        ":reload" => ReplInput::Reload,
        ":reset" => ReplInput::Reset,
        ":source" => ReplInput::Source,
        ":clear" => ReplInput::Clear,
        ":quit" | ":exit" => ReplInput::Quit,
        ":sanitize https-only" => ReplInput::Sanitize(PacUrlSanitize::HttpsOnly),
        ":sanitize all" => ReplInput::Sanitize(PacUrlSanitize::All),
        ":sanitize none" => ReplInput::Sanitize(PacUrlSanitize::None),
        command if command.starts_with(":load ") => {
            let path = command[":load ".len()..].trim();
            if path.is_empty() {
                ReplInput::Invalid(input)
            } else {
                ReplInput::Load(path)
            }
        }
        command if command.starts_with(':') => ReplInput::Invalid(command),
        uri => ReplInput::Evaluate(uri),
    }
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(number) = raw.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = raw.strip_suffix('s') {
        (number, 1.0)
    } else if let Some(number) = raw.strip_suffix('m') {
        (number, 60.0)
    } else if let Some(number) = raw.strip_suffix('h') {
        (number, 3_600.0)
    } else {
        return Err("duration requires an ms, s, m, or h suffix".to_owned());
    };
    let value: f64 = number
        .parse()
        .map_err(|error| format!("duration has an invalid number: {error}"))?;
    let seconds = value * multiplier;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("duration must be finite and greater than zero".to_owned());
    }
    Duration::try_from_secs_f64(seconds).map_err(|error| format!("duration is too large: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TestTerminal {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl TestTerminal {
        fn new(input: &str) -> Self {
            Self {
                input: Cursor::new(input.as_bytes().to_vec()),
                output: Vec::new(),
            }
        }
    }

    impl Write for TestTerminal {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ReplIo for TestTerminal {
        fn read_repl_line(&mut self) -> io::Result<ReplRead> {
            write!(self, "{REPL_PROMPT}")?;
            let mut line = String::new();
            if self.input.read_line(&mut line)? == 0 {
                return Ok(ReplRead::Eof);
            }
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            Ok(ReplRead::Input(line))
        }

        fn clear_repl_screen(&mut self) -> io::Result<()> {
            self.output.extend_from_slice(b"\x1b[2J\x1b[H");
            Ok(())
        }
    }

    #[test]
    fn mode_selection_keeps_stdin_roles_unambiguous() {
        assert_eq!(select_mode(true, false, false), EvalMode::Repl);
        assert_eq!(select_mode(false, false, false), EvalMode::Batch);
        assert_eq!(select_mode(false, true, false), EvalMode::Repl);
        assert_eq!(select_mode(false, true, true), EvalMode::Batch);
        assert_eq!(select_mode(true, false, true), EvalMode::Batch);
    }

    #[test]
    fn source_presence_and_terminal_requirements_cover_every_source_kind() {
        assert!(!has_explicit_source(false, false, false));
        assert!(has_explicit_source(true, false, false));
        assert!(has_explicit_source(false, true, false));
        assert!(has_explicit_source(false, false, true));

        assert!(missing_terminal_source(true, [false; 4]));
        assert!(!missing_terminal_source(false, [false; 4]));
        for index in 0..4 {
            let mut sources = [false; 4];
            sources[index] = true;
            assert!(!missing_terminal_source(true, sources));
        }

        assert!(!has_uri_inputs(&[]));
        assert!(has_uri_inputs(&["https://example.com/".to_owned()]));
    }

    #[test]
    fn every_sanitize_argument_maps_to_its_runtime_mode() {
        assert!(matches!(
            PacUrlSanitize::from(SanitizeArg::HttpsOnly),
            PacUrlSanitize::HttpsOnly
        ));
        assert!(matches!(
            PacUrlSanitize::from(SanitizeArg::All),
            PacUrlSanitize::All
        ));
        assert!(matches!(
            PacUrlSanitize::from(SanitizeArg::None),
            PacUrlSanitize::None
        ));
    }

    #[test]
    fn explicit_source_options_leave_every_positional_for_uris() {
        let inputs = vec!["policy.pac".to_owned(), "https://example.com/".to_owned()];
        assert_eq!(
            split_inputs(inputs.clone(), false),
            (
                Some("policy.pac".to_owned()),
                vec!["https://example.com/".to_owned()]
            )
        );
        assert_eq!(split_inputs(inputs.clone(), true), (None, inputs));
        assert_eq!(split_inputs(Vec::new(), false), (None, Vec::new()));
    }

    #[test]
    fn duration_parser_supports_documented_units() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5m").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_hours(1));
        for invalid in ["1", "0s", "-1s", "NaNs", "infs", "1d"] {
            assert!(parse_duration(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn loading_indicator_records_success_and_drop() {
        let indicator = LoadingIndicator::start(false);
        let state = Arc::clone(&indicator.state);
        assert!(indicator.handle.is_none());
        assert_eq!(state.load(Ordering::Acquire), LOADING_COMPILING);
        indicator.set_stage(LOADING_SCRIPT);
        assert_eq!(state.load(Ordering::Acquire), LOADING_SCRIPT);
        indicator.finish(true);
        assert_eq!(state.load(Ordering::Acquire), LOADING_SUCCEEDED);

        let indicator = LoadingIndicator::start(false);
        let state = Arc::clone(&indicator.state);
        drop(indicator);
        assert_eq!(state.load(Ordering::Acquire), LOADING_STOPPED);
    }

    #[test]
    fn loading_animation_avoids_logs_and_unsuitable_terminals() {
        assert!(loading_animation_enabled(true, true, true));
        for environment in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(!loading_animation_enabled(
                environment.0,
                environment.1,
                environment.2,
            ));
        }
    }

    #[test]
    fn loading_frame_describes_the_current_stage() {
        let mut output = Vec::new();
        write_loading_frame(
            &mut output,
            '⠋',
            LOADING_COMPILING,
            Duration::from_millis(1_200),
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("⠋ Compiling JavaScript engine"));
        assert!(output.contains("1.2s"));

        let mut output = Vec::new();
        write_loading_frame(
            &mut output,
            '⠙',
            LOADING_SCRIPT,
            Duration::from_millis(2_300),
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("⠙ Loading PAC script"));
        assert!(output.contains("2.3s"));
    }

    #[test]
    fn javascript_cache_lives_below_the_rama_home_state() {
        let home = std::path::Path::new("/home/user");
        assert_eq!(
            super::super::js_cache_dir(home),
            home.join(".rama").join("wasm")
        );
    }

    #[test]
    fn raw_terminal_line_end_returns_to_the_first_column() {
        let mut output = Vec::new();
        write_raw_line_end(&mut output).unwrap();
        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn repl_commands_are_distinct_from_uri_input() {
        assert_eq!(parse_repl_input(":help"), ReplInput::Help);
        assert_eq!(
            parse_repl_input(":load path with spaces/proxy.pac"),
            ReplInput::Load("path with spaces/proxy.pac")
        );
        assert_eq!(
            parse_repl_input(":sanitize all"),
            ReplInput::Sanitize(PacUrlSanitize::All)
        );
        assert_eq!(
            parse_repl_input("https://example.com/"),
            ReplInput::Evaluate("https://example.com/")
        );
        assert!(matches!(
            parse_repl_input(":unknown"),
            ReplInput::Invalid(_)
        ));
    }

    #[test]
    fn line_editor_navigates_history_and_restores_the_draft() {
        let history = ["first.example".to_owned(), "second.example".to_owned()];
        let mut state = EditState::default();
        state.insert("draft.example");

        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), &history),
            EditAction::Redraw
        );
        assert_eq!(state.text(), "second.example");
        state.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), &history);
        assert_eq!(state.text(), "first.example");
        state.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &history);
        assert_eq!(state.text(), "second.example");
        state.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &history);
        assert_eq!(state.text(), "draft.example");
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &history),
            EditAction::None
        );

        let mut empty_history = EditState::default();
        assert_eq!(
            empty_history.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE), &[]),
            EditAction::None
        );
    }

    #[test]
    fn line_editor_handles_character_and_cursor_edits() {
        let mut state = EditState::default();
        state.insert("exampl\r\n.com");
        assert_eq!(state.text(), "exampl.com");
        assert_eq!(state.suffix_width(), 0);

        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE), &[]),
            EditAction::Redraw
        );
        assert_eq!(state.suffix_width(), Span::raw("exampl.com").width());
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), &[]),
            EditAction::None
        );
        for _ in 0..6 {
            state.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), &[]);
        }
        state.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE), &[]);
        assert_eq!(state.text(), "example.com");
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &[]),
            EditAction::Redraw
        );
        assert_eq!(state.text(), "exampl.com");
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE), &[]),
            EditAction::Redraw
        );
        assert_eq!(state.text(), "examplcom");

        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE), &[]),
            EditAction::Redraw
        );
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE), &[]),
            EditAction::Redraw
        );
        assert_eq!(state.cursor, state.buffer.len() - 1);
        state.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE), &[]);
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE), &[]),
            EditAction::None
        );
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE), &[]),
            EditAction::None
        );
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &[]),
            EditAction::Submit
        );
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT), &[]),
            EditAction::None
        );
        state.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE), &[]);
        assert_eq!(
            state.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &[]),
            EditAction::None
        );
    }

    #[test]
    fn line_editor_handles_control_keys() {
        let mut state = EditState::default();
        state.insert("one two");
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::Interrupted
        );
        assert_eq!(
            state.handle_key(
                KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::ClearScreen
        );

        state.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(state.cursor, 0);
        state.handle_key(
            KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(state.cursor, state.buffer.len());
        state.handle_key(
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(state.text(), "one ");

        let mut trailing = EditState::default();
        trailing.insert("one  two  ");
        trailing.handle_key(
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(trailing.text(), "one  ");

        let mut empty_word = EditState::default();
        assert_eq!(
            empty_word.handle_key(
                KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::Redraw
        );
        assert!(empty_word.buffer.is_empty());

        state.insert("three");
        state.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
            &[],
        );
        state.handle_key(
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(state.text(), "");

        state.insert("remove");
        state.handle_key(
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(state.text(), "");

        let mut empty = EditState::default();
        assert_eq!(
            empty.handle_key(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::Eof
        );

        let mut nonempty = EditState::default();
        nonempty.insert("xy");
        nonempty.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(
            nonempty.handle_key(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::Redraw
        );
        assert_eq!(nonempty.text(), "y");
        nonempty.handle_key(
            KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
            &[],
        );
        assert_eq!(
            nonempty.handle_key(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
                &[],
            ),
            EditAction::None
        );

        let mut plain = EditState::default();
        for character in "cdaukwl".chars() {
            plain.handle_key(
                KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                &[],
            );
        }
        assert_eq!(plain.text(), "cdaukwl");
    }

    #[test]
    fn repl_help_lists_state_and_source_controls() {
        let mut output = Vec::new();
        write_repl_help(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        for command in [":load", ":reload", ":reset", ":source", ":sanitize"] {
            assert!(output.contains(command), "{command}");
        }
    }

    #[test]
    fn uri_reader_trims_lines_and_skips_blanks() {
        let mut input = &b" https://a.example/ \n\nhttps://b.example/\r\n"[..];
        assert_eq!(
            read_uri_lines(&mut input).unwrap(),
            ["https://a.example/", "https://b.example/"]
        );
    }

    #[test]
    fn piped_uri_reader_never_reuses_source_stdin_or_a_terminal() {
        let mut inputs = Vec::new();
        append_piped_uris(
            &mut inputs,
            false,
            false,
            &mut &b"https://piped.example/\n"[..],
        )
        .unwrap();
        assert_eq!(inputs, ["https://piped.example/"]);

        for (source_from_stdin, stdin_is_terminal) in [(true, false), (false, true)] {
            let mut inputs = Vec::new();
            append_piped_uris(
                &mut inputs,
                source_from_stdin,
                stdin_is_terminal,
                &mut &b"https://must-not-read.example/\n"[..],
            )
            .unwrap();
            assert!(inputs.is_empty());
        }
    }

    #[test]
    fn output_formats_include_successes_and_failures() {
        let outcomes = [
            EvalOutcome {
                uri: "https://a.example/".to_owned(),
                directives: Some("DIRECT".to_owned()),
                error: None,
            },
            EvalOutcome {
                uri: "bad".to_owned(),
                directives: None,
                error: Some("invalid URI".to_owned()),
            },
        ];

        let mut text = Vec::new();
        write_outcomes(&mut text, &outcomes, OutputFormat::Text).unwrap();
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "https://a.example/\tDIRECT\nbad\tERROR\tinvalid URI\n"
        );

        let mut json = Vec::new();
        write_outcomes(&mut json, &outcomes, OutputFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value[0]["directives"], "DIRECT");
        assert_eq!(value[1]["error"], "invalid URI");

        let mut jsonl = Vec::new();
        write_outcomes(&mut jsonl, &outcomes, OutputFormat::Jsonl).unwrap();
        assert_eq!(jsonl.split(|byte| *byte == b'\n').count(), 3);
    }

    #[tokio::test]
    async fn repl_evaluates_with_persistent_state_and_can_reset_it() {
        let source = LoadedSource::load(
            None,
            None,
            Some(
                "var calls = 0; function FindProxyForURL() { calls += 1; return calls === 1 ? 'DIRECT' : 'PROXY stateful.example:8080'; }"
                    .to_owned(),
            ),
            false,
            &mut io::empty(),
        )
        .unwrap();
        let settings = EvalSettings {
            sanitize: PacUrlSanitize::HttpsOnly,
            execution_time_limit: None,
            offline: true,
            fresh: false,
        };
        let session = EvalSession::new(source, settings).unwrap();
        let mut terminal = TestTerminal::new(
            "https://first.example/\nhttps://second.example/\n:reset\nhttps://third.example/\n:quit\n",
        );

        run_repl(&mut terminal, session).await.unwrap();

        let output = String::from_utf8(terminal.output).unwrap();
        assert!(output.contains(
            "pac> https://first.example/  →  DIRECT\n\
             pac> https://second.example/  →  PROXY stateful.example:8080"
        ));
        assert!(output.contains("pac> PAC realm reset\npac> https://third.example/  →  DIRECT"));
    }

    #[tokio::test]
    async fn batch_honors_fail_fast() {
        let source = LoadedSource::load(
            None,
            None,
            Some("function FindProxyForURL() { return 'DIRECT'; }".to_owned()),
            false,
            &mut io::empty(),
        )
        .unwrap();
        let settings = EvalSettings {
            sanitize: PacUrlSanitize::HttpsOnly,
            execution_time_limit: None,
            offline: true,
            fresh: false,
        };
        let session = EvalSession::new(source, settings).unwrap();
        let inputs = vec![
            "mailto:missing-host@example.com".to_owned(),
            "https://valid.example/".to_owned(),
        ];

        let stopped = evaluate_batch(&session, inputs.clone(), true).await;
        assert_eq!(stopped.len(), 1);
        assert!(stopped[0].error.is_some());

        let continued = evaluate_batch(&session, inputs, false).await;
        assert_eq!(continued.len(), 2);
        assert!(continued[0].error.is_some());
        assert_eq!(continued[1].uri, "https://valid.example/");
        assert_eq!(continued[1].directives.as_deref(), Some("DIRECT"));
    }

    #[tokio::test]
    async fn session_load_reload_and_sanitize_rebuild_the_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replacement.pac");
        std::fs::write(
            &path,
            "function FindProxyForURL(url) { return url.indexOf('/private') >= 0 ? 'PROXY visible.example:8080' : 'DIRECT'; }",
        )
        .unwrap();
        let source = LoadedSource::load(
            None,
            None,
            Some("function FindProxyForURL() { return 'DIRECT'; }".to_owned()),
            false,
            &mut io::empty(),
        )
        .unwrap();
        let settings = EvalSettings {
            sanitize: PacUrlSanitize::HttpsOnly,
            execution_time_limit: None,
            offline: true,
            fresh: false,
        };
        let mut session = EvalSession::new(source, settings).unwrap();

        session.load_file(path.clone()).unwrap();
        assert_eq!(
            session
                .evaluate("https://target.example/private")
                .await
                .unwrap()
                .directives
                .to_string(),
            "DIRECT"
        );
        session.set_sanitize(PacUrlSanitize::None).unwrap();
        assert_eq!(
            session
                .evaluate("https://target.example/private")
                .await
                .unwrap()
                .directives
                .to_string(),
            "PROXY visible.example:8080"
        );

        std::fs::write(
            &path,
            "function FindProxyForURL() { return 'HTTPS reloaded.example:443'; }",
        )
        .unwrap();
        session.reload().unwrap();
        assert_eq!(
            session
                .evaluate("https://target.example/private")
                .await
                .unwrap()
                .directives
                .to_string(),
            "HTTPS reloaded.example:443"
        );
    }

    fn eval_command(source: &str, inputs: &[&str]) -> EvalCommand {
        EvalCommand {
            inputs: inputs.iter().map(ToString::to_string).collect(),
            file: None,
            source: Some(source.to_owned()),
            stdin: false,
            format: OutputFormat::Jsonl,
            fail_fast: false,
            fresh: false,
            offline: true,
            sanitize: SanitizeArg::HttpsOnly,
            timeout: None,
        }
    }

    #[tokio::test]
    async fn command_runner_succeeds_only_when_every_evaluation_succeeds() {
        let source = "function FindProxyForURL() { return 'DIRECT'; }";
        run(eval_command(source, &["https://valid.example/"]), false)
            .await
            .unwrap();

        let error = run(
            eval_command(source, &["mailto:first@example.com", "urn:second"]),
            false,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("PAC evaluations failed"));
    }
}
