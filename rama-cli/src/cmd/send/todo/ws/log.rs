use rama::{
    error::{ErrorContext, OpaqueError},
    telemetry::tracing::Level,
};
use std::{env::temp_dir, fs::OpenOptions, path::PathBuf};
use tracing_subscriber::{Layer, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tui_logger::TuiTracingSubscriberLayer;

pub(super) fn init_logger() -> Result<PathBuf, OpaqueError> {
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
                .with_ansi(false)
                .with_writer(log_file)
                .with_filter(filter::LevelFilter::from_level(Level::TRACE)),
        )
        .init();

    tui_logger::init_logger(tui_logger::LevelFilter::Trace).context("init tui logger")?;

    Ok(log_file_path)
}
