//! This example demonstrates how to dynamically choose certificates for incomming requests
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_boring_dynamic_certs --features=boring,http-full
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

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    Context, Layer,
    error::OpaqueError,
    graceful::Shutdown,
    http::server::HttpServer,
    http::{Request, Response},
    layer::ConsumeErrLayer,
    net::{
        address::{Domain, Host},
        tls::server::{ServerAuth, ServerConfig},
        tls::{
            DataEncoding,
            client::ClientHello,
            server::{DynamicCertIssuer, ServerAuthData, ServerCertIssuerData},
        },
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};
use rama_http::IntoResponse;
use rama_net::tls::server::CacheKind;

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, time::Duration};
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

    let issuer = DynamicIssuer::new();

    let tls_server_config = ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
        kind: issuer.into(),
        cache_kind: CacheKind::Disabled,
    }));

    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    let shutdown = Shutdown::default();

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(http_service));

        let tcp_service = (
            ConsumeErrLayer::default(),
            TlsAcceptorLayer::new(acceptor_data),
        )
            .layer(http_service);

        TcpListener::bind("127.0.0.1:64801")
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

struct DynamicIssuer {
    example_data: ServerAuthData,
    second_example_data: ServerAuthData,
    default_data: ServerAuthData,
}

impl DynamicIssuer {
    fn new() -> Self {
        Self {
            example_data: example_self_signed_auth().expect("load example data"),
            second_example_data: second_example_self_signed_auth()
                .expect("load second example data"),
            default_data: example_self_signed_auth().expect("load default data"),
        }
    }
}

impl DynamicCertIssuer for DynamicIssuer {
    async fn issue_cert(
        &self,
        client_hello: ClientHello,
        _server_name: Option<Host>,
    ) -> Result<ServerAuthData, OpaqueError> {
        match client_hello.ext_server_name() {
            Some(host) => match host {
                rama_net::address::Host::Name(domain) => {
                    if domain == &Domain::from_static("example") {
                        return Ok(self.example_data.clone());
                    } else if domain == &Domain::from_static("second.example") {
                        return Ok(self.second_example_data.clone());
                    }
                    Ok(self.example_data.clone())
                }
                rama_net::address::Host::Address(_ip_addr) => Ok(self.default_data.clone()),
            },
            None => Ok(self.example_data.clone()),
        }
    }
}

pub fn example_self_signed_auth() -> Result<ServerAuthData, OpaqueError> {
    Ok(ServerAuthData {
        private_key: DataEncoding::Pem(
            std::str::from_utf8(include_bytes!("./assets/example.com.key"))
                .expect("should decode")
                .try_into()
                .expect("should work"),
        ),
        cert_chain: DataEncoding::Pem(
            std::str::from_utf8(include_bytes!("./assets/example.com.crt"))
                .expect("should decode")
                .try_into()
                .expect("should work"),
        ),
        ocsp: None,
    })
}

pub fn second_example_self_signed_auth() -> Result<ServerAuthData, OpaqueError> {
    Ok(ServerAuthData {
        private_key: DataEncoding::Pem(
            include_str!("./assets/second_example.com.key")
                .try_into()
                .expect("should work"),
        ),
        cert_chain: DataEncoding::Pem(
            include_str!("./assets/second_example.com.crt")
                .try_into()
                .expect("should work"),
        ),
        ocsp: None,
    })
}

async fn http_service<S>(_ctx: Context<S>, _request: Request) -> Result<Response, Infallible> {
    Ok(
        "hello client, you were served by boring tls terminator proxy issuing a dynamic certificate"
            .into_response(),
    )
}
