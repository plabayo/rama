use rama::{
    error::{ErrorContext, OpaqueError},
    telemetry::tracing::Level,
};
use std::{fs::OpenOptions, path::PathBuf};
use tracing_subscriber::{Layer, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tui_logger::TuiTracingSubscriberLayer;

pub(super) fn init_logger(
    log_file_path: Option<PathBuf>,
    use_tui: bool,
) -> Result<Option<PathBuf>, OpaqueError> {
    if let Some(log_file_path) = log_file_path.as_deref() {
        let log_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(log_file_path)
            .context("open log file")?;
        if use_tui {
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
        } else {
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_ansi(false)
                        .with_writer(log_file)
                        .with_filter(filter::LevelFilter::from_level(Level::TRACE)),
                )
                .init();
        }
    }

    Ok(log_file_path)
}
