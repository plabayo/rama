//! `rama inspect`: read one recorded capture file in the terminal.
//!
//! The command itself only decides *what* to load: every format is decoded into
//! the shared [`Timeline`] view model, which [`tui`] renders and [`summary`]
//! prints. Adding a format means adding a decoder, not another viewer.

#![allow(clippy::print_stdout, reason = "CLI: --summary writes to stdout")]

use std::{
    fs::File,
    io::{BufRead, BufReader, IsTerminal as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use clap::{Args, ValueEnum};
use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    http::layer::har,
    inspect::timeline::{Timeline, View},
    quic::qlog,
    telemetry::tracing::subscriber::filter::LevelFilter,
};

mod har_timeline;
mod qlog_timeline;
mod summary;
mod tui;
mod util;

#[cfg(test)]
mod tests;

#[derive(Debug, Args)]
/// inspect a recorded capture file (HAR, qlog) in a terminal viewer
///
/// Supported formats:
///
/// har: HTTP Archive 1.2, including Chrome's `_webSocketMessages` WebSocket frames.
///
/// qlog: qlog main schema draft 14 (QUIC events draft 13), as a contained JSON
/// file or as a JSON text sequence.
///
/// The format is detected from the file extension first and from the file
/// content otherwise; use --format to state it explicitly.
///
/// A capture is decoded straight from the file, but the decoded records are
/// held in memory: --max-records is what bounds that, and --max-size,
/// --max-record-size and --max-body bound what a single file, record or body
/// preview may cost. Exceeding a limit is an error, not a silent truncation.
pub struct InspectCommand {
    /// path of the capture file to inspect
    pub path: PathBuf,

    /// capture format, instead of detecting it
    #[arg(long, short = 'f', value_enum)]
    format: Option<CaptureFormat>,

    /// print a plain-text summary instead of opening the viewer
    ///
    /// Used automatically when stdout is not a terminal.
    #[arg(long, short = 's', default_value_t = false)]
    summary: bool,

    /// maximum capture file size to open, in bytes
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    max_size: u64,

    /// maximum size of one record, in bytes (qlog text-sequence records)
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_record_size: u64,

    /// maximum number of records (HAR entries, qlog events) to read
    ///
    /// A decoded record costs a few KB of memory; raise this for a bigger
    /// capture and expect the footprint to grow with it.
    #[arg(long, default_value_t = 100_000)]
    max_records: usize,

    /// maximum number of bytes shown of any captured body or payload
    #[arg(long, default_value_t = 64 * 1024)]
    max_body: usize,

    /// enable debug logs for tracing (possible via RUST_LOG env as well)
    #[arg(long, short = 'v', default_value_t = false)]
    verbose: bool,
}

/// A capture file format the viewer can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureFormat {
    /// HTTP Archive 1.2.
    Har,
    /// qlog, main schema draft 14.
    Qlog,
}

impl CaptureFormat {
    /// Guess a format from a file extension.
    fn from_extension(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        match extension.as_str() {
            "har" => Some(Self::Har),
            "qlog" | "sqlog" => Some(Self::Qlog),
            _ => None,
        }
    }

    /// Guess a format from the head of a file's content.
    fn from_content(input: &[u8]) -> Option<Self> {
        if qlog::reader::looks_like_qlog(input) {
            Some(Self::Qlog)
        } else if har::spec::looks_like_har(input) {
            Some(Self::Har)
        } else {
            None
        }
    }
}

/// Bounds shared by every decoder.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Maximum number of records to decode.
    pub(crate) max_records: usize,
    /// Maximum number of bytes of any single body or payload preview.
    pub(crate) max_body: usize,
    /// Maximum number of bytes of a single record, and of a whole document that
    /// cannot be decoded incrementally.
    pub(crate) max_bytes: u64,
}

pub async fn run(cfg: InspectCommand) -> Result<(), BoxError> {
    let _tracing = crate::trace::init_tracing(if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::WARN
    })?;

    let limits = Limits {
        max_records: cfg.max_records,
        max_body: cfg.max_body,
        max_bytes: cfg.max_record_size,
    };
    let timeline = tokio::select! {
        biased;
        // Loading a large capture is worth interrupting; nothing is written, so
        // there is no partial state to unwind.
        result = tokio::signal::ctrl_c() => {
            result.context("wait for interrupt")?;
            return Err(BoxError::from_static_str("inspection cancelled"));
        }
        timeline = load(cfg.path, cfg.format, cfg.max_size, limits) => timeline?,
    };

    if cfg.summary || !std::io::stdout().is_terminal() {
        summary::print(&View::new(timeline));
        return Ok(());
    }
    tui::run(View::new(timeline)).await
}

async fn load(
    path: PathBuf,
    format: Option<CaptureFormat>,
    max_size: u64,
    limits: Limits,
) -> Result<Timeline, BoxError> {
    let size = tokio::fs::metadata(&path)
        .await
        .context("read capture file metadata")?
        .len();
    if size > max_size {
        return Err(BoxError::from_static_str("capture file exceeds --max-size")
            .context_field("size", size)
            .context_field("max_size", max_size));
    }
    let source = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("capture")
        .to_owned();

    // Decoding reads the file itself and is CPU-bound: keep it off the reactor
    // thread, and never hold the raw bytes next to the decoded capture.
    tokio::task::spawn_blocking(move || {
        let file = File::open(&path).context("open capture file")?;
        let mut reader = BufReader::new(file);
        let stated = format.or_else(|| CaptureFormat::from_extension(&path));
        let format = if let Some(format) = stated {
            format
        } else {
            // sniff the head, then rewind so the decoder reads the whole file
            let head = reader.fill_buf().context("read capture file")?;
            let format = CaptureFormat::from_content(head)
                .context("unrecognized capture format, use --format to state it")?;
            reader
                .seek(SeekFrom::Start(0))
                .context("rewind capture file")?;
            format
        };
        decode(format, reader, &source, limits)
    })
    .await
    .context("join capture decode task")?
}

pub(crate) fn decode(
    format: CaptureFormat,
    reader: impl BufRead,
    source: &str,
    limits: Limits,
) -> Result<Timeline, BoxError> {
    match format {
        CaptureFormat::Har => har_timeline::decode(reader, source, limits),
        CaptureFormat::Qlog => qlog_timeline::decode(reader, source, limits),
    }
}
