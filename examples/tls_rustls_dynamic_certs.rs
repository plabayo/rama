//! This example demonstrates how to dynamically choose certificates for incomming requests
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

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    Context, Layer,
    error::{ErrorContext, OpaqueError},
    graceful::Shutdown,
    http::{IntoResponse, Request, Response, server::HttpServer},
    layer::ConsumeErrLayer,
    net::{address::Domain, tls::ApplicationProtocol, tls::client::ClientHello},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::{
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

    // Dynamic cert issuing with rustls is not directly supported by rama. But since we can work with
    // native rustls configs, doing this is very much possible (if the issuer doesn't require async)

    let dynamic_issuer = Arc::new(DynamicIssuer::new());
    let config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
        .with_no_client_auth()
        .with_cert_resolver(dynamic_issuer);

    let acceptor_data = TlsAcceptorDataBuilder::from(config)
        .with_alpn_protocols(&[ApplicationProtocol::HTTP_11, ApplicationProtocol::HTTP_2])
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
    default_data: Arc<CertifiedKey>,
}

impl DynamicIssuer {
    fn new() -> Self {
        Self {
            example_data: Arc::new(example_self_signed_auth().expect("load example data")),
            second_example_data: Arc::new(
                second_example_self_signed_auth().expect("load second example data"),
            ),
            default_data: Arc::new(example_self_signed_auth().expect("load default data")),
        }
    }
}

// Currently this only supports a non async dynamic issuer. If you need an async one feel free to open an issue for it,
// as that will require some work in rama because doing that needs access to the `Acceptor` interface.

impl ResolvesServerCert for DynamicIssuer {
    fn resolve(
        &self,
        client_hello: rama_tls_rustls::dep::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // Convert to rama client hello, because we are used to working with that, this is however not needed and can be skipped
        let client_hello = ClientHello::from(client_hello);

        let key = match client_hello.ext_server_name() {
            Some(host) => match host {
                rama_net::address::Host::Name(domain) => {
                    if domain == &Domain::from_static("example") {
                        self.example_data.clone()
                    } else if domain == &Domain::from_static("second.example") {
                        self.second_example_data.clone()
                    } else {
                        self.example_data.clone()
                    }
                }
                rama_net::address::Host::Address(_ip_addr) => self.default_data.clone(),
            },
            None => self.example_data.clone(),
        };
        Some(key)
    }
}

pub fn example_self_signed_auth() -> Result<CertifiedKey, OpaqueError> {
    let cert_chain = pemfile::certs(&mut BufReader::new(
        &include_bytes!("./assets/example.com.crt")[..],
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("collect cert chain")?;

    let priv_key_der = pemfile::private_key(&mut BufReader::new(
        &include_bytes!("./assets/example.com.key")[..],
    ))
    .context("load private key")?
    .context("non empty key")?;

    let provider = Arc::new(aws_lc_rs::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(priv_key_der)
        .context("load private key")?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

pub fn second_example_self_signed_auth() -> Result<CertifiedKey, OpaqueError> {
    let cert_chain = pemfile::certs(&mut BufReader::new(
        &include_bytes!("./assets/second_example.com.crt")[..],
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("collect cert chain")?;

    let priv_key_der = pemfile::private_key(&mut BufReader::new(
        &include_bytes!("./assets/second_example.com.key")[..],
    ))
    .context("load private key")?
    .context("non empty key")?;

    let provider = Arc::new(aws_lc_rs::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(priv_key_der)
        .context("load private key")?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

async fn http_service<S>(_ctx: Context<S>, _request: Request) -> Result<Response, Infallible> {
    Ok(
        "hello client, you were served by rustls tls terminator proxy issuing a dynamic certificate"
            .into_response(),
    )
}
