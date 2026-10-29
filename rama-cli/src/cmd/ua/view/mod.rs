//! A bounded, read-only overview of captured user-agent profiles.
//!
//! Source loading, display summaries, JSON inspection and terminal interaction
//! have separate owners; this module only selects the requested output.

mod display;
mod inspect;
mod render;
mod source;
mod tui;

use clap::Args;
use rama::error::{BoxError, BoxErrorExt as _};
use std::{
    io::{self, IsTerminal as _, Write as _},
    path::PathBuf,
};

#[derive(Debug, Args)]
pub(super) struct ViewCommand {
    /// Profile JSON file, optionally zstd-compressed; omit to read RAMA_FP_DATABASE_URL.
    path: Option<PathBuf>,
    /// Browse the profiles embedded in this rama build instead of a file or database.
    #[arg(long, conflicts_with_all = ["path", "authorized"])]
    embedded: bool,
    /// Read the authorized partition, including authorized archive files.
    #[arg(long)]
    authorized: bool,
    /// Database freshness window, including the current partial UTC day.
    #[arg(long, default_value_t = 14)]
    days: u32,
    /// Print a text summary; also used automatically outside a terminal.
    #[arg(short = 's', long)]
    summary: bool,
    /// Print validated, decoded retained captures as JSON for a file or the embedded profiles.
    #[arg(long, conflicts_with = "summary")]
    json: bool,
}

pub(super) async fn run(command: ViewCommand) -> Result<(), BoxError> {
    if command.json {
        let bytes = if command.embedded {
            tokio::task::spawn_blocking(source::embedded_json).await??
        } else {
            let path = command.path.ok_or_else(|| {
                BoxError::from_static_str("JSON inspection requires a file or --embedded")
            })?;
            tokio::task::spawn_blocking(move || {
                inspect::archive_json(&source::read_profile_file(path)?, command.authorized)
            })
            .await??
        };
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    let source::Overview {
        mut rows,
        label: source_label,
    } = if command.embedded {
        tokio::task::spawn_blocking(source::embedded).await??
    } else {
        source::load(command.path, command.authorized, command.days).await?
    };
    display::sort_rows(&mut rows);
    if command.summary || !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        let mut output = io::stdout().lock();
        writeln!(output, "{} profiles — {source_label}", rows.len())?;
        for row in rows {
            writeln!(output, "{}", row.summary())?;
        }
        return Ok(());
    }
    tokio::task::spawn_blocking(move || tui::run(rows, source_label)).await?
}
