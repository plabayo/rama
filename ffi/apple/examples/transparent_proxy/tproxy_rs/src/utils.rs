use std::{path::PathBuf, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::subscriber::{
        self, EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _,
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
        _ = STORAGE_DIR.set(path);
    }
}

pub(super) fn storage_dir() -> Option<&'static PathBuf> {
    STORAGE_DIR.get()
}

#[derive(Debug)]
struct TraceContext;

fn setup_tracing() -> Result<TraceContext, BoxError> {
    // Default: DEBUG for all crates except the H2 codec, which emits one
    // `debug!` log per frame and generates >600 messages/second under load,
    // triggering system-log quarantine.  Override at runtime via RUST_LOG.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug,rama_http_core::h2::codec=warn"));

    let stderr_layer = subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stderr);

    let oslog_layer = OsLogger::new("org.ramaproxy.example.tproxy", "extension-rust");

    subscriber::registry()
        .with(env_filter)
        .with(stderr_layer)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subscriber")?;

    Ok(TraceContext)
}
