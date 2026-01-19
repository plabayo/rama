//! This example demonstrates how to create a TLS termination proxy, forwarding the
//! plain transport stream to another service.
//!
//! This example is an alternative version of the [tls_rustls_termination](./tls_rustls_termination.rs) example,
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

// rama provides everything out of the box to build a TLS termination proxy

use rama::{
    Layer,
    extensions::ExtensionsRef,
    graceful::Shutdown,
    http::{Request, Response, server::HttpServer},
    layer::{ConsumeErrLayer, GetInputExtensionLayer},
    net::{
        address::HostWithPort,
        forwarded::Forwarded,
        stream::SocketInfo,
        tls::{
            SecureTransport,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
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
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

// everything else is provided by the standard library, community crates or tokio

use std::{convert::Infallible, time::Duration};

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

    let tls_server_config = ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()));

    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    let shutdown = Shutdown::default();

    // create tls proxy
    shutdown.spawn_task_fn(async move |guard| {
        let tcp_service = (
            TlsAcceptorLayer::new(acceptor_data).with_store_client_hello(true),
            GetInputExtensionLayer::new(async move |st: SecureTransport| {
                let client_hello = st.client_hello().unwrap();
                tracing::debug!("secure connection established: client hello = {client_hello:?}");
            }),
        )
            .into_layer(
                Forwarder::new(
                    Executor::graceful(guard.clone()),
                    HostWithPort::local_ipv4(62801),
                )
                .with_connector(
                    // ha proxy protocol used to forwarded the client original IP
                    HaProxyClientLayer::tcp()
                        .into_layer(TcpConnector::new(Executor::graceful(guard.clone()))),
                ),
            );

        TcpListener::bind("127.0.0.1:63801", Executor::graceful(guard.clone()))
            .await
            .expect("bind TCP Listener: tls")
            .serve(tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(service_fn(http_service));

        let tcp_service =
            (ConsumeErrLayer::default(), HaProxyServerLayer::new()).into_layer(http_service);

        TcpListener::bind("127.0.0.1:62801", exec)
            .await
            .expect("bind TCP Listener: http")
            .serve(tcp_service)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_service(req: Request) -> Result<Response, Infallible> {
    // REMARK: builds on the assumption that we are using the haproxy protocol
    let client_addr = req
        .extensions()
        .get::<Forwarded>()
        .unwrap()
        .client_socket_addr()
        .unwrap();
    // REMARK: builds on the assumption that rama's TCP service sets this for you :)
    let proxy_addr = req.extensions().get::<SocketInfo>().unwrap().peer_addr();

    Ok(Response::new(
        format!(
            "hello client {client_addr}, you were served by tls terminator proxy {proxy_addr}\r\n"
        )
        .into(),
    ))
}
