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
    rt::Executor,
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    tls::rustls::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer, self_signed_client_auth},
        dep::rustls::{
            ALL_VERSIONS, RootCertStore,
            server::{ServerConfig, WebPkiClientVerifier},
        },
        server::{TlsAcceptorData, TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};

// everything else is provided by the standard library, community crates or tokio
use std::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
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

    let (tls_client_data, tls_server_data) = {
        let (client_cert_chain, client_priv_key) = self_signed_client_auth().unwrap();
        let client_cert = client_cert_chain[0].clone();

        let tls_client_data =
            TlsConnectorDataBuilder::new_with_client_auth(client_cert_chain, client_priv_key)
                .expect("connector with client auth")
                .with_no_cert_verifier()
                .with_alpn_protocols_http_auto()
                .with_server_name(SERVER_AUTHORITY.into_host())
                .with_env_key_logger()
                .expect("connector with env keylogger")
                .build();

        // More complex use cases like this aren't directly supported by rama, but that is no problem, we can work with rustls
        // native configs, so that means if rustls can do it: so can we, and so can you.
        // We can either directly convert [`rustls::ServerConfig`] into [`TlsAcceptorData`] or we can convert it into
        // [`TlsAcceptorDataBuilder`] so we can make use of some of the utils rama provides.

        let builder = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS);
        let mut root_cert_storage = RootCertStore::empty();
        root_cert_storage.add(client_cert).unwrap();
        let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
            .build()
            .expect("new webpki client verifier");
        let builder = builder.with_client_cert_verifier(cert_verifier);

        let (server_cert_chain, server_priv_key) = self_signed_client_auth().unwrap();
        let server_config = builder
            .with_single_cert(server_cert_chain, server_priv_key)
            .expect("server config with single cert");

        // Directly convert [`rustls::ServerConfig`] to [`TlsAcceptorData`]
        let _tls_server_data = TlsAcceptorData::from(server_config.clone());

        // Or convert [`rustls::ServerConfig`] to [`TlsAcceptorDataBuilder`] to make use of some of the utils rama provides
        let tls_server_data = TlsAcceptorDataBuilder::from(server_config)
            .with_alpn_protocols_http_auto()
            .with_env_key_logger()
            .expect("acceptor with env keylogger")
            .build();

        (tls_client_data, tls_server_data)
    };

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
