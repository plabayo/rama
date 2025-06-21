use opentelemetry_otlp::{SpanExporter, WithHttpConfig};
use rama::{
    http::{client::EasyHttpWebClient, service::opentelemetry::OtelExporter},
    net::client::pool::http::HttpPooledConnectorConfig,
    telemetry::{
        opentelemetry::{
            KeyValue,
            sdk::{Resource, trace::SdkTracerProvider},
            trace::TracerProvider,
        },
        tracing::{self, layer},
    },
};
use std::io::IsTerminal as _;
use tracing_subscriber::{
    EnvFilter, filter::Directive, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

pub fn init_tracing(default_directive: impl Into<Directive>) {
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        init_structured(default_directive);
        tracing::trace!("structured (OTEL) tracing init complete");
    } else {
        init_default(default_directive);
        tracing::trace!("default tracing init complete");
    }
}

fn init_default(default_directive: impl Into<Directive>) {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(default_directive.into())
                .from_env_lossy(),
        )
        .init();
}

fn init_structured(default_directive: impl Into<Directive>) {
    let svc = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(None)
        .with_connection_pool(HttpPooledConnectorConfig::default())
        .expect("build http exporter client service")
        .build();
    let client = OtelExporter::new(svc);

    let exportor = SpanExporter::builder()
        .with_http()
        .with_http_client(client)
        .build()
        .unwrap();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exportor)
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new("service.name", "rama"))
                .build(),
        )
        .build();

    let tracer = provider.tracer("rama-cli");
    let telemetry = layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(telemetry)
        .with(
            tracing_subscriber::fmt::Layer::new()
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
        .init();
}
