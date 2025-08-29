//! This example demonstrates how to dynamically choose certificates for incoming requests
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_rustls_dynamic_certs --features=rustls,http-full
//! ```
//!
//! Test if the correct certificates are returned by making curl resolve example and second.example to
//! the localhost address on which we expose this service.
//!
//! Example certificate:
//! ```sh
//! curl -vik --resolve example:64802:127.0.0.1 https://example:64802
//! ```
//! Output
//! ```
//! * Server certificate:
//! *  subject: CN=example.com
//! *  start date: Dec  9 20:05:17 2024 GMT
//! *  expire date: Dec  7 20:05:17 2034 GMT
//! *  issuer: CN=example.com
//! *  SSL certificate verify result: self signed certificate (18), continuing anyway.
//! ```
//!
//! Second example certificate:
//! ```sh
//! curl -vik --resolve second.example:64802:127.0.0.1 https://second.example:64802
//! ```
//! Output
//! ```
//! * Server certificate:
//! *  subject: CN=second.example.com
//! *  start date: Dec  9 20:08:11 2024 GMT
//! *  expire date: Dec  7 20:08:11 2034 GMT
//! *  issuer: CN=second.example.com
//! *  SSL certificate verify result: self signed certificate (18), continuing anyway.
//! ```
//!
//! Fallback to to default (example certificate) if no matches are found:
//! ```sh
//! curl -vik https://127.0.0.1:64802
//! ```
//! Output
//! ```
//! * Server certificate:
//! *  subject: CN=example.com
//! *  start date: Dec  9 20:05:17 2024 GMT
//! *  expire date: Dec  7 20:05:17 2034 GMT
//! *  issuer: CN=example.com
//! *  SSL certificate verify result: self signed certificate (18), continuing anyway.
//! ```

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    Context, Layer,
    error::{ErrorContext, OpaqueError},
    graceful::Shutdown,
    http::service::web::response::IntoResponse,
    http::{Request, Response, server::HttpServer},
    layer::ConsumeErrLayer,
    net::tls::client::ClientHello,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::level_filters::LevelFilter,
    tls::rustls::{
        RamaFrom,
        dep::{
            pemfile,
            rustls::{
                ALL_VERSIONS, ServerConfig, crypto::aws_lc_rs, server::ResolvesServerCert,
                sign::CertifiedKey,
            },
        },
        server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, io::BufReader, sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    // Dynamic certs using [`ResolvesServerCert`] in rustls are loaded synchronously, if you need to
    // load them in an async way, see example `tls_rustls_dynamic_config` for how to provide a different
    // [`rustls::ServerConfig`] depending on received client_hello in an async context

    let dynamic_issuer = Arc::new(DynamicIssuer::new());
    let config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
        .with_no_client_auth()
        .with_cert_resolver(dynamic_issuer);

    let acceptor_data = TlsAcceptorDataBuilder::from(config)
        .with_alpn_protocols_http_auto()
        .with_env_key_logger()
        .expect("with env keylogger")
        .build();

    // create http server
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(http_service));

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(acceptor_data),
        )
            .into_layer(http_service);

        TcpListener::bind("127.0.0.1:64802")
            .await
            .expect("bind TCP Listener: http")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(3))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
struct DynamicIssuer {
    example_data: Arc<CertifiedKey>,
    second_example_data: Arc<CertifiedKey>,
}

impl DynamicIssuer {
    fn new() -> Self {
        let example_data = Arc::new(
            load_certificate(
                include_bytes!("./assets/example.com.crt"),
                include_bytes!("./assets/example.com.key"),
            )
            .expect("load example data"),
        );

        let second_example_data = Arc::new(
            load_certificate(
                include_bytes!("./assets/second_example.com.crt"),
                include_bytes!("./assets/second_example.com.key"),
            )
            .expect("load second example data"),
        );

        Self {
            example_data,
            second_example_data,
        }
    }
}

impl ResolvesServerCert for DynamicIssuer {
    fn resolve(
        &self,
        client_hello: rama::tls::rustls::dep::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // Convert to rama client hello, because we are used to working with that, this is however not needed and can be skipped
        let client_hello = ClientHello::rama_from(client_hello);

        let key = match client_hello.ext_server_name() {
            Some(domain) => {
                if domain == "example" {
                    self.example_data.clone()
                } else if domain == "second.example" {
                    self.second_example_data.clone()
                } else {
                    self.example_data.clone()
                }
            }
            None => self.example_data.clone(),
        };
        Some(key)
    }
}

fn load_certificate(cert_chain: &[u8], private_key: &[u8]) -> Result<CertifiedKey, OpaqueError> {
    let cert_chain = pemfile::certs(&mut BufReader::new(cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .context("collect cert chain")?;

    let priv_key_der = pemfile::private_key(&mut BufReader::new(private_key))
        .context("load private key")?
        .context("non empty key")?;

    let provider = Arc::new(aws_lc_rs::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(priv_key_der)
        .context("load private key")?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

async fn http_service(_ctx: Context, _request: Request) -> Result<Response, Infallible> {
    Ok(
        "hello client, you were served by rustls tls terminator proxy issuing a dynamic certificate"
            .into_response(),
    )
}
