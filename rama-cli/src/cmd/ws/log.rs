use rama::{
    error::{ErrorContext, OpaqueError},
    telemetry::tracing::Level,
};
use std::{env::temp_dir, fs::OpenOptions, path::PathBuf};
use tracing_subscriber::{Layer, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tui_logger::TuiTracingSubscriberLayer;

pub(super) fn init_logger(cfg: super::CliCommandWs) -> Result<PathBuf, OpaqueError> {
    let (trace_filter, tui_level) = if cfg.verbose {
        (
            filter::LevelFilter::from_level(Level::DEBUG),
            tui_logger::LevelFilter::Debug,
        )
    } else {
        (
            filter::LevelFilter::from_level(Level::INFO),
            tui_logger::LevelFilter::Info,
        )
    };

    let log_file_path = temp_dir().join("rama-ws.txt");

    let log_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_file_path)
        .context("open log file")?;
    tracing_subscriber::registry()
        .with(TuiTracingSubscriberLayer)
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_writer(log_file)
                .with_filter(trace_filter),
        )
        .init();

    tui_logger::init_logger(tui_level).context("init tui logger")?;

    Ok(log_file_path)
}
