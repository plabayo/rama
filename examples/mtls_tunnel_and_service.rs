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

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)
use rama::tls::rustls::dep::{pki_types::ServerName, tokio_rustls::TlsConnector};

// rama provides everything out of the box to build mtls web services and proxies
use rama::{
    error::BoxError,
    graceful::Shutdown,
    http::{
        layer::trace::TraceLayer,
        response::{Html, Redirect},
        server::HttpServer,
        service::web::WebService,
    },
    layer::TraceErrLayer,
    net::tls::client::ClientConfig,
    net::tls::client::{ClientAuth, ServerVerifyMode},
    net::tls::server::{ClientVerifyMode, SelfSignedData, ServerAuth, ServerConfig},
    net::tls::DataEncoding,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::client::TlsConnectorData,
    tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer},
    Context, Layer,
};

// everything else is provided by the standard library, community crates or tokio
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const SERVER_DOMAIN: &str = "127.0.0.1";
const SERVER_ADDR: &str = "127.0.0.1:63014";
const TUNNEL_ADDR: &str = "127.0.0.1:62014";

#[derive(Debug)]
struct TunnelState {
    client_data: TlsConnectorData,
}

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
        expose_client_cert: true,
        server_verify_mode: ServerVerifyMode::Disable,
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
    let tls_server_data =
        TlsAcceptorData::try_from(tls_server_config).expect("create tls acceptor data for server");

    // create mtls web server
    shutdown.spawn_task_fn(|guard| async move {
        let executor = Executor::graceful(guard.clone());

        let tcp_service = TlsAcceptorLayer::new(tls_server_data).layer(
            HttpServer::auto(executor).service(
                TraceLayer::new_for_http().layer(
                    WebService::default()
                        .get("/", Redirect::temporary("/hello"))
                        .get("/hello", Html("<h1>Hello, authorized client!</h1>")),
                ),
            ),
        );

        tracing::info!("start mtls (https) web service: {}", SERVER_ADDR);
        TcpListener::bind(SERVER_ADDR)
            .await
            .unwrap_or_else(|e| {
                panic!("bind TCP Listener ({SERVER_ADDR}): mtls (https): web service: {e}")
            })
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create mtls tunnel proxy
    shutdown.spawn_task_fn(|guard| async move {
        tracing::info!("start mTLS TCP Tunnel Proxys: {}", TUNNEL_ADDR);
        TcpListener::build_with_state(TunnelState {
            client_data: tls_client_data,
        })
        .bind(TUNNEL_ADDR)
        .await
        .expect("bind TCP Listener: mTLS TCP Tunnel Proxys")
        .serve_graceful(guard, TraceErrLayer::new().layer(service_fn(serve_conn)))
        .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

/// L4 Proxy Service
async fn serve_conn(ctx: Context<TunnelState>, mut source: TcpStream) -> Result<(), BoxError> {
    let state = ctx.state();

    let target = TcpStream::connect(SERVER_ADDR).await?;
    let tls_connector = TlsConnector::from(state.client_data.shared_client_config());
    let server_name = ServerName::try_from(SERVER_DOMAIN)
        .expect("parse server name")
        .to_owned();
    let mut target = tls_connector.connect(server_name, target).await?;

    match tokio::io::copy_bidirectional(&mut source, &mut target).await {
        Ok(_) => Ok(()),
        Err(err) => {
            if rama::tcp::utils::is_connection_error(&err) {
                Ok(())
            } else {
                Err(err)
            }
        }
    }?;
    Ok(())
}
