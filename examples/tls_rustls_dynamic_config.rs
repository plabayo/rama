//! This example demonstrates how to dynamically choose a rustls config depending on the incomming client hello
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_rustls_dynamic_config --features=rustls,http-full
//! ```
//!
//! Test if the correct certificates are returned by making curl resolve example and second.example to
//! the localhost address on which we expose this service.
//!
//! Example certificate:
//! ```sh
//! curl -vik --resolve example:64804:127.0.0.1 https://example:64804
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
//! curl -vik --resolve second.example:64804:127.0.0.1 https://second.example:64804
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
//! Connection should fail if no matches are found:
//! ```sh
//! curl -vik https://127.0.0.1:64804
//! ```
//! Output
//! ```
//! * Closing connection
//! curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 127.0.0.1:64804
//! ```

// rama provides everything out of the box to build a TLS termination proxy with a dynamic rustls config
use rama::{
    Context, Layer,
    error::{ErrorContext, OpaqueError},
    graceful::Shutdown,
    http::{IntoResponse, Request, Response, server::HttpServer},
    layer::ConsumeErrLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::{
        dep::{
            pemfile,
            pki_types::{CertificateDer, PrivateKeyDer},
        },
        server::DynamicConfigProvider,
        server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};

use tokio::time::sleep;

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, io::BufReader, sync::Arc, time::Duration};
use tracing::metadata::LevelFilter;
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
    let dynamic_config_provider = Arc::new(DynamicConfig);

    // create http server
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(http_service));

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(dynamic_config_provider.into()),
        )
            .into_layer(http_service);

        TcpListener::bind("127.0.0.1:64804")
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
struct DynamicConfig;

impl DynamicConfigProvider for DynamicConfig {
    async fn get_config(
        &self,
        client_hello: rama_tls_rustls::dep::rustls::server::ClientHello<'_>,
    ) -> Result<Arc<rama_tls_rustls::dep::rustls::ServerConfig>, OpaqueError> {
        let (cert_chain, key_der) = match client_hello.server_name() {
            Some(name) => match name {
                "example" => load_example_certificate().await,
                "second.example" => load_second_example_certificate().await,
                name => Err(OpaqueError::from_display(format!(
                    "server name {} not recognized",
                    name
                ))),
            },
            _ => Err(OpaqueError::from_display(
                "server name required for this server to work",
            )),
        }?;

        let config = TlsAcceptorDataBuilder::new(cert_chain, key_der)
            .unwrap()
            .with_alpn_protocols_http_auto()
            .with_env_key_logger()
            .expect("with env key logger")
            .into_rustls_config();

        Ok(Arc::new(config))
    }
}

async fn load_example_certificate()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    // Fake io delay
    sleep(Duration::from_millis(10)).await;
    parse_certificate(
        include_bytes!("./assets/example.com.crt"),
        include_bytes!("./assets/example.com.key"),
    )
}

async fn load_second_example_certificate()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    // Fake io delay
    sleep(Duration::from_millis(10)).await;
    parse_certificate(
        include_bytes!("./assets/second_example.com.crt"),
        include_bytes!("./assets/second_example.com.key"),
    )
}

fn parse_certificate(
    cert_chain: &[u8],
    private_key: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    let cert_chain = pemfile::certs(&mut BufReader::new(cert_chain))
        .collect::<Result<Vec<_>, _>>()
        .context("collect cert chain")?;

    let priv_key_der = pemfile::private_key(&mut BufReader::new(private_key))
        .context("load private key")?
        .context("non empty key")?;

    Ok((cert_chain, priv_key_der))
}

async fn http_service<S>(_ctx: Context<S>, _request: Request) -> Result<Response, Infallible> {
    Ok(
        "hello client, you were served by rustls tls terminator proxy issuing a dynamic config"
            .into_response(),
    )
}
