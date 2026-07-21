//! This example demonstrates how to dynamically choose certificates for incoming requests
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin tls_boring_dynamic_certs --features=boring,http-full
//! ```
//!
//! Test if the correct certificates are returned by making curl resolve example and second.example to
//! the localhost address on which we expose this service.
//!
//! Example certificate:
//! ```sh
//! curl -vik --resolve example:64801:127.0.0.1 https://example:64801
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
//! curl -vik --resolve second.example:64801:127.0.0.1 https://second.example:64801
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
//! curl -vik https://127.0.0.1:64801
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

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    error::{BoxError, ErrorContext},
    graceful::Shutdown,
    http::{Request, Response, server::HttpServer, service::web::response::IntoResponse},
    layer::ConsumeErrLayer,
    net::address::Domain,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::server::{
        BoringServerConfigExt as _, CacheKind, ServerCertIssuerData, TlsAcceptorLayer,
    },
    tls::{
        client::ClientHello,
        server::{DynamicCertIssuer, ServerAuthData, TlsServerConfig},
    },
};

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, env, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let issuer = DynamicIssuer::new();
    let bind_address = env::var("RAMA_TLS_BORING_DYNAMIC_CERTS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:64801".to_owned());

    let tls_server_config = TlsServerConfig::new().with_cert_issuer(ServerCertIssuerData {
        kind: issuer.into(),
        cache_kind: CacheKind::Disabled,
    });

    let shutdown = Shutdown::default();

    // create http server
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(service_fn(http_service));

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(tls_server_config),
        )
            .into_layer(http_service);

        TcpListener::bind_address(bind_address, exec)
            .await
            .expect("bind TCP Listener: http")
            .serve(tcp_service)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(3))
        .await
        .expect("graceful shutdown");
}

struct DynamicIssuer {
    example_data: ServerAuthData,
    second_example_data: ServerAuthData,
}

impl DynamicIssuer {
    fn new() -> Self {
        Self {
            example_data: example_self_signed_auth().expect("load example data"),
            second_example_data: second_example_self_signed_auth()
                .expect("load second example data"),
        }
    }
}

impl DynamicCertIssuer for DynamicIssuer {
    async fn issue_cert(
        &self,
        client_hello: ClientHello,
        _server_name: Option<Domain>,
    ) -> Result<ServerAuthData, BoxError> {
        match client_hello.ext_server_name() {
            Some(domain) => {
                if domain == "example" {
                    return Ok(self.example_data.clone());
                } else if domain == "second.example" {
                    return Ok(self.second_example_data.clone());
                }
                Ok(self.example_data.clone())
            }
            None => Ok(self.example_data.clone()),
        }
    }
}

pub fn example_self_signed_auth() -> Result<ServerAuthData, BoxError> {
    parse_auth_data(
        include_bytes!("../assets/example.com.crt"),
        include_bytes!("../assets/example.com.key"),
    )
}

pub fn second_example_self_signed_auth() -> Result<ServerAuthData, BoxError> {
    parse_auth_data(
        include_bytes!("../assets/second_example.com.crt"),
        include_bytes!("../assets/second_example.com.key"),
    )
}

fn parse_auth_data(cert_chain: &[u8], private_key: &[u8]) -> Result<ServerAuthData, BoxError> {
    let cert_chain = CertificateDer::pem_slice_iter(cert_chain)
        .collect::<Result<Vec<_>, _>>()
        .context("collect cert chain")?;

    let private_key = PrivateKeyDer::from_pem_slice(private_key).context("load private key")?;

    Ok(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    })
}

async fn http_service(_request: Request) -> Result<Response, Infallible> {
    Ok(
        "hello client, you were served by boring tls terminator proxy issuing a dynamic certificate"
            .into_response(),
    )
}
