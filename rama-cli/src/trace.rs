use rama::{
    error::{BoxError, ErrorContext as _},
    http::client::EasyHttpWebClient,
    rt::Executor,
    telemetry::{
        opentelemetry::{
            KeyValue,
            collector::OtelExporter,
            sdk::{Resource, trace::SdkTracerProvider},
            semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION},
            trace::TracerProvider,
        },
        tracing::{
            self, Level,
            appender::{NonBlocking, NonBlockingBuilder, WorkerGuard},
            layer,
            subscriber::{
                EnvFilter, Layer as _,
                filter::{self, Directive},
                fmt,
                layer::SubscriberExt,
                util::SubscriberInitExt,
            },
        },
    },
    tls::client::TlsClientConfig,
};

use std::{
    fs::OpenOptions,
    io::{IsTerminal as _, Write},
    path::Path,
};

/// Keeps the tracing writer thread alive; dropping it flushes pending records.
///
/// Hold it for the lifetime of the command.
#[must_use = "dropping the guard stops the tracing writer thread"]
#[derive(Debug)]
pub struct TracingGuard {
    _worker: WorkerGuard,
}

/// Write records on a dedicated thread. A `write(2)` per event on a runtime
/// worker stalls that worker whenever the reader of stderr (or the disk) is
/// slow; non-lossy, so a full buffer applies backpressure instead of dropping.
fn dedicated_writer<W: Write + Send + 'static>(writer: W) -> (NonBlocking, TracingGuard) {
    let (writer, worker) = NonBlockingBuilder::default()
        .lossy(false)
        .thread_name("rama-tracing")
        .finish(writer);
    (writer, TracingGuard { _worker: worker })
}

pub fn init_tracing(default_directive: impl Into<Directive>) -> Result<TracingGuard, BoxError> {
    init_tracing_with_overrides(default_directive, [])
}

pub fn init_tracing_with_overrides(
    default_directive: impl Into<Directive>,
    overrides: impl IntoIterator<Item = Directive>,
) -> Result<TracingGuard, BoxError> {
    let default_directive = default_directive.into();
    let overrides: Vec<_> = overrides.into_iter().collect();
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        init_structured(default_directive, &overrides)
    } else {
        init_default(default_directive, &overrides)
    }
}

fn init_default(
    default_directive: Directive,
    overrides: &[Directive],
) -> Result<TracingGuard, BoxError> {
    let ansi = std::io::stderr().is_terminal();
    let (stderr, guard) = dedicated_writer(std::io::stderr());
    tracing::subscriber::registry()
        .with(fmt::layer().with_ansi(ansi).with_writer(stderr))
        .with(env_filter(default_directive, overrides))
        .try_init()
        .context("try init (default) tracing subscriber")?;

    Ok(guard)
}

fn init_structured(
    default_directive: Directive,
    overrides: &[Directive],
) -> Result<TracingGuard, BoxError> {
    let svc = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(TlsClientConfig::default_http())
        .with_default_http_connector(Executor::default())
        .with_default_connection_pool()
        .build_client();
    let exportor = OtelExporter::from_env_http(svc).context("build OTLP HTTP span exporter")?;

    let resource = Resource::builder()
        .with_attribute(KeyValue::new(
            SERVICE_NAME,
            rama::utils::info::NAME.to_owned(),
        ))
        .with_attribute(KeyValue::new(
            SERVICE_VERSION,
            rama::utils::info::VERSION.to_owned(),
        ))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exportor)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("rama-cli");
    let telemetry = layer().with_tracer(tracer);

    let ansi = std::io::stderr().is_terminal();
    let (stderr, guard) = dedicated_writer(std::io::stderr());
    tracing::subscriber::registry()
        .with(telemetry)
        .with(
            tracing::subscriber::fmt::Layer::new()
                .with_ansi(ansi)
                .with_writer(stderr)
                .json()
                .flatten_event(true),
        )
        .with(env_filter(default_directive, overrides))
        .try_init()
        .context("try init (structured) tracing subscriber")?;

    Ok(guard)
}

fn env_filter(default_directive: Directive, overrides: &[Directive]) -> EnvFilter {
    overrides.iter().cloned().fold(
        EnvFilter::builder()
            .with_default_directive(default_directive)
            .from_env_lossy(),
        EnvFilter::add_directive,
    )
}

pub fn init_tracing_file(path: &Path) -> Result<TracingGuard, BoxError> {
    if let Some(parent_dir) = path.parent() {
        std::fs::create_dir_all(parent_dir)
            .context("create dirs for tracing file")
            .with_context_debug_field("path", || path.to_owned())?;
    }

    let log_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .context("open log file")?;

    let (log_file, guard) = dedicated_writer(log_file);
    tracing::subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_writer(log_file)
                .with_filter(filter::LevelFilter::from_level(Level::TRACE)),
        )
        .init();

    Ok(guard)
}
