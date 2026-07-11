use std::{path::PathBuf, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::{
        apple::oslog::{OsLogLayer, Privacy, SpanMode},
        subscriber::{self, filter, layer::SubscriberExt as _, util::SubscriberInitExt as _},
    },
};

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
    let oslog_layer = OsLogLayer::new("org.ramaproxy.example.tproxy", "extension-rust")?
        .with_privacy(Privacy::Public)
        .with_span_mode(SpanMode::Signposts)
        .with_span_context(true);

    subscriber::registry()
        .with(filter::LevelFilter::DEBUG)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subscriber")?;

    Ok(TraceContext)
}
