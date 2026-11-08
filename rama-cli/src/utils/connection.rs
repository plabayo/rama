//! The connection drain flag every serve command shares.

use clap::Args;
use rama::cli::DEFAULT_CONNECTION_GRACE;
use std::time::Duration;

#[derive(Debug, Clone, Args)]
pub struct ConnectionGraceArgs {
    #[arg(long, default_value_t = DEFAULT_CONNECTION_GRACE.as_secs_f64())]
    /// at most how many seconds a draining connection may still run before it is dropped
    ///
    /// A connection drains once it reaches `--timeout`, or when the server shuts down; on
    /// shutdown, `--graceful` can end it sooner.
    timeout_grace: f64,
}

impl Default for ConnectionGraceArgs {
    fn default() -> Self {
        Self {
            timeout_grace: DEFAULT_CONNECTION_GRACE.as_secs_f64(),
        }
    }
}

impl ConnectionGraceArgs {
    /// The grace as a duration; a negative or invalid value falls back to the default.
    pub fn grace(&self) -> Duration {
        Duration::try_from_secs_f64(self.timeout_grace).unwrap_or(DEFAULT_CONNECTION_GRACE)
    }
}
