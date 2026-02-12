use rama::{
    error::{BoxError, ErrorContext},
    telemetry::tracing::{
        self, Level,
        subscriber::{Layer, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::{fs::OpenOptions, path::PathBuf};
use tui_logger::TuiTracingSubscriberLayer;

pub(super) fn init_logger(
    log_file_path: Option<PathBuf>,
    use_tui: bool,
) -> Result<Option<PathBuf>, BoxError> {
    if let Some(log_file_path) = log_file_path.as_deref() {
        let log_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(log_file_path)
            .context("open log file")?;
        if use_tui {
            tracing::subscriber::registry()
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
            tracing::subscriber::registry()
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
