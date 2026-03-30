use std::{path::PathBuf, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::subscriber::{
        self, filter, layer::SubscriberExt as _, util::SubscriberInitExt as _,
    },
};
use tracing_oslog::OsLogger;

pub(super) fn init_tracing() -> bool {
    static CTX: OnceLock<Option<TraceContext>> = OnceLock::new();
    CTX.get_or_init(|| match setup_tracing() {
        Ok(ctx) => Some(ctx),
        Err(err) => {
            eprintln!("failed to setup tracing: {err}");
            None
        }
    })
    .is_some()
}

static STORAGE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub(super) fn set_storage_dir(path: Option<PathBuf>) {
    if let Some(path) = path {
        let _ = STORAGE_DIR.set(path);
    }
}

pub(super) fn storage_dir() -> PathBuf {
    STORAGE_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir().join("rama_tproxy_example"))
}

#[derive(Debug)]
struct TraceContext;

fn setup_tracing() -> Result<TraceContext, BoxError> {
    let stderr_layer = subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stderr);

    let oslog_layer = OsLogger::new("org.ramaproxy.example.tproxy", "extension-rust");

    subscriber::registry()
        .with(filter::LevelFilter::DEBUG) // TODO: make customisable log level
        .with(stderr_layer)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subsriber")?;

    Ok(TraceContext)
}
