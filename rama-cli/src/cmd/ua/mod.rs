//! Parse user-agent headers and export counted profiles.

use std::{
    io::{self, Write as _},
    path::PathBuf,
};

use clap::{Args, Subcommand};
mod view;

use rama::{
    error::BoxError,
    ua::{UserAgent, profile::ProfileArchiveLimits},
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
    /// Browse profiles from a JSON file or the fingerprint database.
    View(view::ViewCommand),
}

#[derive(Debug, Args)]
pub(crate) struct ExportProfilesCommand {
    /// Destination JSON document; published after all profiles validate.
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
    /// Maximum number of profiles in the document.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().profiles)]
    pub max_profiles: usize,
    /// Maximum output bytes; exceeding the limit publishes no document.
    #[arg(long, default_value_t = ProfileArchiveLimits::default().bytes)]
    pub max_output_bytes: usize,
}

pub async fn run(command: UaCommand) -> Result<(), BoxError> {
    match command.command {
        UaSubcommand::View(command) => view::run(command).await,
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
                writeln!(output, "User-Agent: {}", user_agent.header_str())?;
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
        UaSubcommand::Export(command) => {
            crate::cmd::serve::fp::export_counted_profiles(command).await
        }
    }
}
