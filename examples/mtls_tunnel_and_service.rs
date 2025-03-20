//! This example demonstrates how to create a mTLS tunnel proxy and a mTLS web service.
//! The mTLS tunnel proxy is a server that accepts mTLS connections, and forwards the mTLS transport stream to another service.
//! The mTLS web service is a server that accepts mTLS connections, and serves a simple web page.
//! You can learn more about this kind of proxy in [the rama book](https://ramaproxy.org/book/) at the [mTLS Tunnel Proxy](https://ramaproxy.org/book/proxies/tls.html) section.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example mtls_tunnel_and_service --features=http-full,rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63014`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k -v https://127.0.0.1:63014
//! ```
//!
//! This won't work as the client is not authorized. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62014/hello
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a body with `Hello, authorized client!`.

// rama provides everything out of the box to build mtls web services and proxies
use rama::{
    Layer,
    graceful::Shutdown,
    http::{
        layer::trace::TraceLayer,
        response::{Html, Redirect},
        server::HttpServer,
        service::web::WebService,
    },
    layer::TraceErrLayer,
    net::address::{Authority, Host},
    net::tls::client::{ClientAuth, ServerVerifyMode},
    net::tls::client::{ClientConfig, ClientHelloExtension},
    net::tls::server::{ClientVerifyMode, SelfSignedData, ServerAuth, ServerConfig},
    net::tls::{ApplicationProtocol, DataEncoding},
    rt::Executor,
    tcp::client::service::Forwarder,
    tcp::client::service::TcpConnector,
    tcp::server::TcpListener,
    tls_rustls::client::{TlsConnectorData, TlsConnectorLayer},
    tls_rustls::server::{TlsAcceptorData, TlsAcceptorLayer},
};

// everything else is provided by the standard library, community crates or tokio
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const LOCALHOST: Host = Host::Address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
const SERVER_AUTHORITY: Authority = Authority::new(LOCALHOST, 63014);
const TUNNEL_AUTHORITY: Authority = Authority::new(LOCALHOST, 62014);

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

    // generate client connector data
    let tls_client_data = TlsConnectorData::try_from(ClientConfig {
        client_auth: Some(ClientAuth::SelfSigned),
        server_verify_mode: Some(ServerVerifyMode::Disable),
        extensions: Some(vec![ClientHelloExtension::ServerName(Some(
            SERVER_AUTHORITY.into_host(),
        ))]),
        ..Default::default()
    })
    .expect("create tls connector data for client");
    let tls_client_cert_chain: Vec<_> = tls_client_data
        .client_auth_cert_chain()
        .into_iter()
        .flatten()
        .map(|cert| cert.as_ref().to_vec())
        .collect();

    // generate server cert
    let mut tls_server_config =
        ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()));
    tls_server_config.client_verify_mode =
        ClientVerifyMode::ClientAuth(DataEncoding::DerStack(tls_client_cert_chain));
    tls_server_config.application_layer_protocol_negotiation = Some(vec![
        ApplicationProtocol::HTTP_2,
        ApplicationProtocol::HTTP_11,
    ]);
    let tls_server_data =
        TlsAcceptorData::try_from(tls_server_config).expect("create tls acceptor data for server");

    // create mtls web server
    shutdown.spawn_task_fn(async |guard| {
        let executor = Executor::graceful(guard.clone());

        let tcp_service = TlsAcceptorLayer::new(tls_server_data).into_layer(
            HttpServer::auto(executor).service(
                TraceLayer::new_for_http().into_layer(
                    WebService::default()
                        .get("/", Redirect::temporary("/hello"))
                        .get("/hello", Html("<h1>Hello, authorized client!</h1>")),
                ),
            ),
        );

        tracing::info!("start mtls (https) web service: {}", SERVER_AUTHORITY);
        TcpListener::bind(SERVER_AUTHORITY.to_string())
            .await
            .unwrap_or_else(|e| {
                panic!("bind TCP Listener ({SERVER_AUTHORITY}): mtls (https): web service: {e}")
            })
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create mtls tunnel proxy
    shutdown.spawn_task_fn(async |guard| {
        tracing::info!("start mTLS TCP Tunnel Proxys: {}", TUNNEL_AUTHORITY);

        let forwarder = Forwarder::new(SERVER_AUTHORITY).connector(
            TlsConnectorLayer::tunnel(Some(SERVER_AUTHORITY.into_host()))
                .with_connector_data(tls_client_data)
                .into_layer(TcpConnector::new()),
        );

        // L4 Proxy Service
        TcpListener::bind(TUNNEL_AUTHORITY.to_string())
            .await
            .expect("bind TCP Listener: mTLS TCP Tunnel Proxys")
            .serve_graceful(guard, TraceErrLayer::new().into_layer(forwarder))
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
