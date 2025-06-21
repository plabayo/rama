//! An example to showcase how one can build an authenticated socks5 CONNECT proxy server.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_connect_proxy_over_tls --features=socks5,boring,http-full
//! ```
//!
//! # Expected output
//!
//! The socks5-over-tls will start and listen on a free (TCP) port.
//! and there will also be a local plain text http server listening on another free (TCP) port.
//!
//! Sadly this will not be possible to run through curl as most tools
//! do not support socks5 within TLS. The advantage of a Rama is
//! that it empowers you to do whatever you want, no limits except for your own creativity.
//!
//! Do share with us your fantastical creations, we love to hear about it.
//!
//! This example finishes automatically as it tests itself with a rama socks5 client
//! that goes through Tls, with the power of rama. Be empowered, be brave, go forward.

use rama::{
    Context, Service,
    http::{
        Body, BodyExtractExt, Request, client::HttpConnector, server::HttpServer,
        service::web::Router,
    },
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::{ConnectorService, EstablishedClientConnection},
        tls::client::ServerVerifyMode,
        tls::server::{SelfSignedData, ServerAuth, ServerConfig},
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::{Socks5Acceptor, Socks5Auth, Socks5ProxyConnector},
    rt::Executor,
    tcp::{client::service::TcpConnector, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::{
        client::{TlsConnector, TlsConnectorDataBuilder},
        server::{TlsAcceptorData, TlsAcceptorService},
    },
};

use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    let proxy_socket_addr = spawn_socks5_over_tls_server().await;
    let http_socket_addr = spawn_http_server().await;

    tracing::info!(
        network.peer.address = %proxy_socket_addr.ip_addr(),
        network.peer.port = %proxy_socket_addr.port(),
        server.address = %http_socket_addr.ip_addr(),
        server.port = %http_socket_addr.port(),
        "local servers up and running",
    );

    let tls_conn_data = TlsConnectorDataBuilder::new()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = HttpConnector::new(Socks5ProxyConnector::required(
        TlsConnector::secure(TcpConnector::new()).with_connector_data(tls_conn_data),
    ));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new("john", "secret"))),
    });

    let uri = format!("http://{http_socket_addr}/ping");
    tracing::info!(
        url.full = %uri,
        "try to establish proxied connection over SOCKS5 within a TLS Tunnel",
    );

    let request = Request::builder()
        .uri(uri.clone())
        .body(Body::empty())
        .expect("build simple GET request");

    let EstablishedClientConnection {
        ctx,
        req,
        conn: http_service,
    } = client
        .connect(ctx, request)
        .await
        .expect("establish a proxied connection ready to make http requests");

    tracing::info!(
        url.full = %uri,
        "try to make GET http request and try to receive response text",
    );

    let resp = http_service
        .serve(ctx, req)
        .await
        .expect("make http request via socks5 proxy within TLS tunnel")
        .try_into_string()
        .await
        .expect("get response text");

    assert_eq!("pong", resp);
    tracing::info!("ping-pong succeeded, bye now!")
}

async fn spawn_socks5_over_tls_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63011))
        .await
        .expect("bind socks5-over-tls CONNECT proxy on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of socks5-over-tls proxy server")
        .into();

    let socks5_acceptor =
        Socks5Acceptor::default().with_auth(Socks5Auth::username_password("john", "secret"));

    let tls_server_config = ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()));
    let acceptor_data =
        TlsAcceptorData::try_from(tls_server_config).expect("create tls acceptor data");

    let secure_socks5_acceptor = TlsAcceptorService::new(acceptor_data, socks5_acceptor, false);

    tokio::spawn(tcp_service.serve(secure_socks5_acceptor));

    bind_addr
}

async fn spawn_http_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63012))
        .await
        .expect("bind HTTP server on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of http server")
        .into();

    let app = Router::new().get("/ping", "pong");
    let server = HttpServer::auto(Executor::default()).service(Arc::new(app));

    tokio::spawn(tcp_service.serve(server));

    bind_addr
}
