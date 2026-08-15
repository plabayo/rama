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
            self, Level, layer,
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

use std::{fs::OpenOptions, io::IsTerminal as _, path::Path};

pub fn init_tracing(default_directive: impl Into<Directive>) -> Result<(), BoxError> {
    init_tracing_with_overrides(default_directive, [])
}

pub fn init_tracing_with_overrides(
    default_directive: impl Into<Directive>,
    overrides: impl IntoIterator<Item = Directive>,
) -> Result<(), BoxError> {
    let default_directive = default_directive.into();
    let overrides: Vec<_> = overrides.into_iter().collect();
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        init_structured(default_directive, &overrides)
    } else {
        init_default(default_directive, &overrides)
    }
}

fn init_default(default_directive: Directive, overrides: &[Directive]) -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(std::io::stderr),
        )
        .with(env_filter(default_directive, overrides))
        .try_init()
        .context("try init (default) tracing subscriber")?;

    Ok(())
}

fn init_structured(default_directive: Directive, overrides: &[Directive]) -> Result<(), BoxError> {
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

    tracing::subscriber::registry()
        .with(telemetry)
        .with(
            tracing::subscriber::fmt::Layer::new()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(std::io::stderr)
                .json()
                .flatten_event(true),
        )
        .with(env_filter(default_directive, overrides))
        .try_init()
        .context("try init (structured) tracing subscriber")?;

    Ok(())
}

fn env_filter(default_directive: Directive, overrides: &[Directive]) -> EnvFilter {
    overrides.iter().cloned().fold(
        EnvFilter::builder()
            .with_default_directive(default_directive)
            .from_env_lossy(),
        EnvFilter::add_directive,
    )
}

pub fn init_tracing_file(path: &Path) -> Result<(), BoxError> {
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

    tracing::subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_writer(log_file)
                .with_filter(filter::LevelFilter::from_level(Level::TRACE)),
        )
        .init();

    Ok(())
}
