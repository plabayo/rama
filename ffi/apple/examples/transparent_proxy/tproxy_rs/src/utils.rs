use std::sync::OnceLock;

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        address::HostWithPort, apple::networkextension::tproxy::TransparentProxyFlowMeta,
        proxy::ProxyTarget,
    },
    telemetry::tracing::subscriber::{
        self, filter, layer::SubscriberExt as _, util::SubscriberInitExt as _,
    },
};
use tracing_oslog::OsLogger;

/// Resolve a remote target endpoint from extensions.
pub(super) fn resolve_target_from_extensions(
    ext: &rama::extensions::Extensions,
) -> Option<HostWithPort> {
    ext.get::<ProxyTarget>()
        .cloned()
        .map(|target| target.0)
        .or_else(|| {
            ext.get::<TransparentProxyFlowMeta>()
                .and_then(|meta| meta.remote_endpoint.clone())
        })
}

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

#[derive(Debug)]
struct TraceContext;

fn setup_tracing() -> Result<TraceContext, BoxError> {
    let stderr_layer = subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stderr);

    let oslog_layer = OsLogger::new("org.ramaproxy.example.tproxy", "transparent-proxy");

    subscriber::registry()
        .with(filter::LevelFilter::DEBUG) // TODO: make customisable log level
        .with(stderr_layer)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subsriber")?;

    Ok(TraceContext)
}
