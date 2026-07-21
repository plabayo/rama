//! This example demonstrates how to create a mTLS tunnel proxy and a mTLS web service.
//! The mTLS tunnel proxy is a server that accepts mTLS connections, and forwards the mTLS transport stream to another service.
//! The mTLS web service is a server that accepts mTLS connections, and serves a simple web page.
//! You can learn more about this kind of proxy in [the rama book](https://ramaproxy.org/book/) at the [mTLS Tunnel Proxy](https://ramaproxy.org/book/proxies/tls.html) section.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin mtls_tunnel_and_service --features=http-full,rustls,aws-lc
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
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    graceful::Shutdown,
    http::{
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            WebService,
            response::{Html, Redirect},
        },
    },
    layer::TraceErrLayer,
    net::{address::SocketAddress, proxy::IoForwardService},
    rt::Executor,
    tcp::{client::service::TcpConnector, proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::rustls::{
        client::{TlsConnectorLayer, self_signed_client_auth},
        server::TlsAcceptorLayer,
    },
    tls::{
        KeyLogIntent,
        client::{ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientConfig},
        server::{ClientVerifyMode, ServerAuthData, TlsServerConfig},
    },
};

// everything else is provided by the standard library, community crates or tokio

use std::time::Duration;

const SERVER_AUTHORITY: SocketAddress = SocketAddress::local_ipv4(63014);
const TUNNEL_AUTHORITY: SocketAddress = SocketAddress::local_ipv4(62014);

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

    let shutdown = Shutdown::default();

    let (tls_client_data, tls_server_data) = {
        let (client_cert_chain, client_priv_key) = self_signed_client_auth().unwrap();
        let client_cert = client_cert_chain[0].clone();

        let tls_client_data = TlsClientConfig::default_http()
            .with_client_auth(ClientAuth::Single(ClientAuthData {
                cert_chain: client_cert_chain,
                private_key: client_priv_key,
            }))
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_name(SERVER_AUTHORITY.ip_addr.into());

        let (server_cert_chain, server_priv_key) = self_signed_client_auth().unwrap();
        let tls_server_data = TlsServerConfig::new()
            .with_single_cert(ServerAuthData {
                cert_chain: server_cert_chain,
                private_key: server_priv_key,
                ocsp: None,
            })
            .with_client_verify(ClientVerifyMode::ClientAuth(vec![client_cert]))
            .with_alpn_http_auto()
            .with_keylog(KeyLogIntent::Environment);

        (tls_client_data, tls_server_data)
    };

    // create mtls web server
    shutdown.spawn_task_fn(async |guard| {
        let executor = Executor::graceful(guard.clone());

        let tcp_service = TlsAcceptorLayer::new(tls_server_data).into_layer(
            HttpServer::auto(executor.clone()).service(
                TraceLayer::new_for_http().into_layer(
                    WebService::default()
                        .with_get("/", Redirect::temporary("/hello"))
                        .with_get("/hello", Html("<h1>Hello, authorized client!</h1>")),
                ),
            ),
        );

        tracing::info!(
            server.address = %SERVER_AUTHORITY.ip_addr,
            server.port = %SERVER_AUTHORITY.port,
            "start mtls (https) web service",
        );
        TcpListener::bind_address(SERVER_AUTHORITY.to_string(), executor)
            .await
            .unwrap_or_else(|e| {
                panic!("bind TCP Listener ({SERVER_AUTHORITY}): mtls (https): web service: {e}")
            })
            .serve(tcp_service)
            .await;
    });

    // create mtls tunnel proxy
    shutdown.spawn_task_fn(async |guard| {
        tracing::info!(
            server.address = %TUNNEL_AUTHORITY.ip_addr,
            server.port = %TUNNEL_AUTHORITY.port,
            "start mTLS TCP Tunnel Proxy",
        );

        let exec = Executor::graceful(guard.clone());
        let forwarder = (
            TraceErrLayer::new(),
            IoToProxyBridgeIoLayer::new(SERVER_AUTHORITY).with_connector(
                TlsConnectorLayer::tunnel(Some(SERVER_AUTHORITY.ip_addr.into()))
                    .with_base_config(tls_client_data)
                    .into_layer(TcpConnector::new()),
            ),
        )
            .into_layer(IoForwardService::new(exec.clone()));

        // L4 Proxy Service
        TcpListener::bind_address(TUNNEL_AUTHORITY, exec)
            .await
            .expect("bind TCP Listener: mTLS TCP Tunnel Proxys")
            .serve(forwarder)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
