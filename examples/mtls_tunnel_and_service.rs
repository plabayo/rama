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
    net::{
        address::{Authority, Host},
        tls::ApplicationProtocol,
    },
    rt::Executor,
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    tls_rustls::{
        client::{TlsConnectorData, TlsConnectorLayer},
        dep::rustls,
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
};
use rama_net::tls::KeyLogIntent;
use rama_tls_rustls::{
    client::{client_root_certs, self_signed_client_auth},
    dep::rustls::{ALL_VERSIONS, ClientConfig, server::WebPkiClientVerifier},
    key_log::KeyLogFile,
    verify::NoServerCertVerifier,
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

    // TODO right now this is a rustls example, but we can and should add boring here aswel

    let (tls_client_data, tls_server_data) = {
        let (client_cert_chain, client_priv_key) = self_signed_client_auth().unwrap();

        let mut client_conf = ClientConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_root_certificates(client_root_certs())
            .with_client_auth_cert(client_cert_chain.clone(), client_priv_key)
            .unwrap();

        client_conf
            .dangerous()
            .set_certificate_verifier(Arc::new(NoServerCertVerifier::default()));

        let builder = rustls::ServerConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS);
        let mut root_cert_storage = rustls::RootCertStore::empty();
        root_cert_storage.add(client_cert_chain[0].clone()).unwrap();
        let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
            .build()
            .unwrap();
        let builder = builder.with_client_cert_verifier(cert_verifier);

        let (server_cert_chain, server_priv_key) = self_signed_client_auth().unwrap();
        let mut server_config = builder
            .with_single_cert(server_cert_chain, server_priv_key)
            .unwrap();

        if let Some(path) = KeyLogIntent::Environment.file_path() {
            let key_logger = Arc::new(KeyLogFile::new(path).unwrap());
            server_config.key_log = key_logger.clone();
            client_conf.key_log = key_logger;
        };

        client_conf.alpn_protocols = vec![
            ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
            ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
        ];
        server_config.alpn_protocols = client_conf.alpn_protocols.clone();

        let tls_client_data = TlsConnectorData {
            client_config: Arc::new(client_conf),
            server_name: Some(SERVER_AUTHORITY.into_host()),
            store_server_certificate_chain: false,
        };

        let tls_server_data = TlsAcceptorData::from(server_config);

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
