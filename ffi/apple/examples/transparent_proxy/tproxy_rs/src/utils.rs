use std::{fs::create_dir_all, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        address::HostWithPort, apple::networkextension::tproxy::TransparentProxyFlowMeta,
        proxy::ProxyTarget,
    },
    telemetry::tracing::{
        appender,
        subscriber::{self, filter, layer::SubscriberExt as _, util::SubscriberInitExt as _},
    },
};

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
#[allow(unused)]
struct TraceContext(appender::non_blocking::WorkerGuard);

fn setup_tracing() -> Result<TraceContext, BoxError> {
    const FILE_NAME: &str = "trace.log";

    let log_file_dir_path = std::env::home_dir()
        .context("fetch home dir")?
        .join(".rama")
        .join("examples")
        .join("tproxy");
    create_dir_all(&log_file_dir_path).context("create log parent dir")?;

    let file_appender = appender::rolling::never(log_file_dir_path, FILE_NAME);
    let (non_blocking, guard) = appender::non_blocking(file_appender);

    let file_layer = subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(non_blocking);

    subscriber::registry()
        .with(filter::LevelFilter::DEBUG) // TODO: make customisable log level
        .with(file_layer)
        .try_init()
        .context("init tracing subsriber")?;

    Ok(TraceContext(guard))
}
