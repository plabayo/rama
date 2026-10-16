//! A bounded, read-only overview of captured user-agent profiles.
//!
//! Source loading, display summaries, JSON inspection and terminal interaction
//! have separate owners; this module only selects the requested output.

mod display;
mod inspect;
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

pub(super) async fn run(command: ViewCommand) -> Result<(), BoxError> {
    if command.json {
        let path = command
            .path
            .ok_or_else(|| BoxError::from_static_str("JSON inspection requires an archive file"))?;
        let bytes = tokio::task::spawn_blocking(move || {
            inspect::archive_json(&source::read_profile_file(path)?, command.authorized)
        })
        .await??;
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    let source::Overview {
        rows,
        label: source_label,
    } = source::load(command.path, command.authorized, command.days).await?;
    if command.summary || !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        let mut output = io::stdout().lock();
        writeln!(output, "{} profiles — {source_label}", rows.len())?;
        for row in rows {
            writeln!(output, "{}", row.label)?;
        }
        return Ok(());
    }
    tokio::task::spawn_blocking(move || tui::run(rows, source_label)).await?
}
