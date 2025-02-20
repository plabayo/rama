//! This example demonstrates how to create a TLS termination proxy, forwarding the
//! plain transport stream to another service.
//!
//! This example is an alternative version of the [tls_termination](./tls_termination.rs) example,
//! but using boring instead of rustls.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_boring_termination --features=boring,haproxy,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63801`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v https://127.0.0.1:62801
//! ```
//!
//! The above will fail, due to not being haproxy encoded, but also because it is not a tls service...
//!
//! This one will work however:
//!
//! ```sh
//! curl -k -v https://127.0.0.1:63801
//! ```
//!
//! You should see a response with `HTTP/1.0 200 ok` and the body `Hello world!`.

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    Context, Layer,
    graceful::Shutdown,
    http::{Request, Response, server::HttpServer},
    layer::{ConsumeErrLayer, GetExtensionLayer},
    net::{
        forwarded::Forwarded,
        stream::SocketInfo,
        tls::server::{SelfSignedData, ServerAuth, ServerConfig},
    },
    proxy::haproxy::{
        client::HaProxyLayer as HaProxyClientLayer, server::HaProxyLayer as HaProxyServerLayer,
    },
    rt::Executor,
    service::service_fn,
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    tls::{
        boring::server::{TlsAcceptorData, TlsAcceptorLayer},
        types::SecureTransport,
    },
};

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

    let tls_server_config = ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()));

    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    let shutdown = Shutdown::default();

    // create tls proxy
    shutdown.spawn_task_fn(|guard| async move {
        let tcp_service = (
            TlsAcceptorLayer::new(acceptor_data).with_store_client_hello(true),
            GetExtensionLayer::new(|st: SecureTransport| async move {
                let client_hello = st.client_hello().unwrap();
                tracing::debug!(?client_hello, "secure connection established");
            }),
        )
            .layer(Forwarder::new(([127, 0, 0, 1], 62801)).connector(
                // ha proxy protocol used to forwarded the client original IP
                HaProxyClientLayer::tcp().layer(TcpConnector::new()),
            ));

        TcpListener::bind("127.0.0.1:63801")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(service_fn(http_service));

        let tcp_service =
            (ConsumeErrLayer::default(), HaProxyServerLayer::new()).layer(http_service);

        TcpListener::bind("127.0.0.1:62801")
            .await
            .expect("bind TCP Listener: http")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_service<S>(ctx: Context<S>, _request: Request) -> Result<Response, Infallible> {
    // REMARK: builds on the assumption that we are using the haproxy protocol
    let client_addr = ctx
        .get::<Forwarded>()
        .unwrap()
        .client_socket_addr()
        .unwrap();
    // REMARK: builds on the assumption that rama's TCP service sets this for you :)
    let proxy_addr = ctx.get::<SocketInfo>().unwrap().peer_addr();

    Ok(Response::new(
        format!(
            "hello client {client_addr}, you were served by tls terminator proxy {proxy_addr}\r\n"
        )
        .into(),
    ))
}
