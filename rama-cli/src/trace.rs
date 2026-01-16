use rama::{
    error::{BoxError, ErrorContext as _},
    http::{client::EasyHttpWebClient, service::opentelemetry::OtelExporter},
    net::client::pool::http::HttpPooledConnectorConfig,
    rt::Executor,
    telemetry::{
        opentelemetry::{
            KeyValue,
            collector::{SpanExporter, WithHttpConfig},
            sdk::{Resource, trace::SdkTracerProvider},
            semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION},
            trace::TracerProvider,
        },
        tracing::{
            self, layer,
            subscriber::{
                EnvFilter, filter::Directive, fmt, layer::SubscriberExt, util::SubscriberInitExt,
            },
        },
    },
};

use std::io::IsTerminal as _;

pub fn init_tracing(default_directive: impl Into<Directive>) -> Result<(), BoxError> {
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        init_structured(default_directive)
    } else {
        init_default(default_directive)
    }
}

fn init_default(default_directive: impl Into<Directive>) -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(default_directive.into())
                .from_env_lossy(),
        )
        .try_init()
        .context("try init (default) tracing subscriber")?;

    Ok(())
}

fn init_structured(default_directive: impl Into<Directive>) -> Result<(), BoxError> {
    let svc = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(None)
        .with_default_http_connector(Executor::default())
        .try_with_connection_pool(HttpPooledConnectorConfig::default())
        .context("build http exporter client service")?
        .build_client();
    let client = OtelExporter::new(svc);

    let exportor = SpanExporter::builder()
        .with_http()
        .with_http_client(client)
        .build()
        .context("build span exporter w/ rama http client")?;

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
        .with(
            EnvFilter::builder()
                .with_default_directive(default_directive.into())
                .from_env_lossy(),
        )
        .try_init()
        .context("try init (structured) tracing subscriber")?;

    Ok(())
}
