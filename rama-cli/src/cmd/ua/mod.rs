//! Parse user-agent headers and export counted profiles.

use std::{
    io::{self, Write as _},
    path::PathBuf,
};

use crate::{
    cmd::serve::fp::{compact_profile_archive, export_counted_profiles},
    utils::terminal::display_text,
};
use clap::{Args, Subcommand};
mod compare;
mod view;

use rama::{
    error::BoxError,
    ua::{UserAgent, profile::format::archive::ProfileArchiveLimits},
};

#[derive(Debug, Args)]
/// Parse user-agent headers and export captured profiles.
pub struct UaCommand {
    #[command(subcommand)]
    command: UaSubcommand,
}

#[derive(Debug, Subcommand)]
enum UaSubcommand {
    /// Describe a User-Agent header using Rama's parser.
    Parse {
        /// Complete User-Agent header value, quoted as one argument.
        user_agent: String,
        /// Print JSON instead of a human-readable summary.
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Export fresh counted profiles from RAMA_FP_DATABASE_URL.
    Export(ExportProfilesCommand),
    /// Compile an archive file into the profile set that rama-ua embeds.
    Compact(CompactProfilesCommand),
    /// Browse profiles from a JSON file or the fingerprint database.
    View(view::ViewCommand),
    /// Compare complete retained captures from two counted archives.
    Compare(compare::CompareCommand),
}

#[derive(Debug, Args)]
pub(crate) struct ExportProfilesCommand {
    /// Destination JSON document; published after exported profiles validate.
    #[arg(long)]
    pub output: PathBuf,
    /// Number of UTC day buckets, including the current partial day.
    #[arg(long, default_value_t = 14)]
    pub days: u32,
    /// Export the authorized partition instead of public observations.
    #[arg(long)]
    pub authorized: bool,
    /// Additively import retained legacy rows before export (writes fp_v2 only).
    #[arg(long)]
    pub import_legacy: bool,
    /// Replace an existing destination after a complete successful export.
    #[arg(long)]
    pub replace: bool,
    /// Keep profiles holding only imported legacy fields. Profile selection draws only
    /// captured flows, so such profiles cannot be emulated and are left out by default.
    #[arg(long)]
    pub include_legacy: bool,
    /// Write the precompiled profile set that rama-ua embeds.
    #[arg(long)]
    pub embed: bool,
    /// Leave out the profile recorded for this exact User-Agent; repeatable.
    #[arg(
        long = "exclude-user-agent",
        value_name = "USER_AGENT",
        requires = "embed"
    )]
    pub exclude_user_agents: Vec<Box<str>>,
    /// Maximum database profiles examined, including skipped profiles.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().profiles)]
    pub max_profiles: usize,
    /// Maximum output bytes; exceeding the limit publishes no document.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().bytes)]
    pub max_output_bytes: usize,
}

#[derive(Debug, Args)]
pub(crate) struct CompactProfilesCommand {
    /// Versioned profile archive JSON document or a compiled profile set.
    pub input: PathBuf,
    /// Destination; published after the compiled set validates.
    #[arg(long)]
    pub output: PathBuf,
    /// Replace an existing destination after a successful compaction.
    #[arg(long)]
    pub replace: bool,
    /// Keep profiles holding only imported legacy fields. Profile selection draws only
    /// captured flows, so such profiles cannot be emulated and are left out by default.
    #[arg(long)]
    pub include_legacy: bool,
    /// Leave out the profile recorded for this exact User-Agent; repeatable.
    #[arg(long = "exclude-user-agent", value_name = "USER_AGENT")]
    pub exclude_user_agents: Vec<Box<str>>,
    /// Maximum input bytes.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().bytes)]
    pub max_input_bytes: usize,
    /// Maximum output bytes; exceeding the limit publishes no document.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().bytes)]
    pub max_output_bytes: usize,
}

pub async fn run(command: UaCommand) -> Result<(), BoxError> {
    match command.command {
        UaSubcommand::View(command) => view::run(command).await,
        UaSubcommand::Compare(command) => compare::run(&command),
        UaSubcommand::Parse { user_agent, json } => {
            let user_agent = UserAgent::new(user_agent);
            let mut output = io::stdout().lock();
            if json {
                let value = serde_json::json!({
                    "user_agent": user_agent.header_str(),
                    "kind": user_agent.ua_kind(),
                    "version": user_agent.ua_version(),
                    "platform": user_agent.platform(),
                    "device": user_agent.device(),
                });
                serde_json::to_writer_pretty(&mut output, &value)?;
                output.write_all(b"\n")?;
            } else {
                writeln!(
                    output,
                    "User-Agent: {}",
                    display_text(user_agent.header_str())
                )?;
                writeln!(
                    output,
                    "Family:     {}",
                    user_agent.ua_kind().map_or("unknown", |kind| kind.as_str())
                )?;
                writeln!(
                    output,
                    "Version:    {}",
                    user_agent
                        .ua_version()
                        .map(|version| version.to_string())
                        .as_deref()
                        .unwrap_or("unknown")
                )?;
                writeln!(
                    output,
                    "Platform:   {}",
                    user_agent
                        .platform()
                        .map_or("unknown", |platform| platform.as_str())
                )?;
                writeln!(
                    output,
                    "Device:     {}",
                    user_agent
                        .device()
                        .map_or("unknown", |device| device.as_str())
                )?;
            }
            Ok(())
        }
        UaSubcommand::Export(command) => export_counted_profiles(command).await,
        UaSubcommand::Compact(command) => {
            tokio::task::spawn_blocking(move || compact_profile_archive(&command)).await?
        }
    }
}
