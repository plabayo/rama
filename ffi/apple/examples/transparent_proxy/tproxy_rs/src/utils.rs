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
    let oslog_layer = OsLogLayer::new_for_main_bundle(
        "org.ramaproxy.example.tproxy",
        "extension-rust",
    )?
        .with_privacy(Privacy::PublicMessagePrivateFields)
        .with_span_mode(SpanMode::Signposts)
        .with_span_context(true);
    let target_filter = trace_filter();

    subscriber::registry()
        .with(target_filter)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subscriber")?;

    Ok(TraceContext)
}

fn trace_filter() -> filter::Targets {
    filter::Targets::new()
        .with_default(filter::LevelFilter::INFO)
        .with_target("rama_tproxy_example", filter::LevelFilter::DEBUG)
        .with_target(
            "rama_net_apple_networkextension::tproxy",
            filter::LevelFilter::DEBUG,
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::telemetry::tracing::Level;

    #[test]
    fn trace_filter_omits_protocol_debug_noise() {
        let filter = trace_filter();
        assert!(filter.would_enable("rama_tproxy_example::http", &Level::DEBUG));
        assert!(filter.would_enable(
            "rama_net_apple_networkextension::tproxy::engine",
            &Level::DEBUG
        ));
        assert!(filter.would_enable("rama_http_core::proto", &Level::INFO));
        assert!(!filter.would_enable("rama_http_core::proto", &Level::DEBUG));
        assert!(!filter.would_enable("rama_tproxy_example", &Level::TRACE));
    }
}
