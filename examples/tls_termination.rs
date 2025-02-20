//! This example demonstrates how to create a TLS termination proxy, forwarding the
//! plain transport stream to another service.
//!
//! See also the [mtls_tunnel_and_services](./mtls_tunnel_and_services.rs) example for a more complex example
//! of how to use the `TlsAcceptorLayer` and `TlsAcceptorService` to create a mTLS tunnel and services.
//!
//! This proxy is an example of a TLS termination proxy, which is a server that accepts TLS connections,
//! decrypts the TLS and forwards the plain transport stream to another service.
//! You can learn more about this kind of proxy in [the rama book](https://ramaproxy.org/book/) at the [TLS Termination Proxy](https://ramaproxy.org/book/proxies/tls.html) section.
//!
//! This example also demonstrates the full HaProxy (v2, tcp) protocol usage,
//! should you ever need it. We expect that mostly you will need it from a service POV,
//! in case you host your rama-driven proxy on a cloud provider such as fly.io. Such
//! providers set you behind a cloud provider, so the only way to get the client original IP is using something like this.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_termination --features=haproxy,http-full,rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63800`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v https://127.0.0.1:62800
//! ```
//!
//! The above will fail, due to not being haproxy encoded, but also because it is not a tls service...
//!
//! This one will work however:
//!
//! ```sh
//! curl -k -v https://127.0.0.1:63800
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
    layer::ConsumeErrLayer,
    net::forwarded::Forwarded,
    net::stream::{SocketInfo, Stream},
    proxy::haproxy::{
        client::HaProxyLayer as HaProxyClientLayer, server::HaProxyLayer as HaProxyServerLayer,
    },
    service::service_fn,
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    tls::std::server::{TlsAcceptorData, TlsAcceptorLayer},
};
use rama_net::tls::server::{SelfSignedData, ServerAuth, ServerConfig};

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, time::Duration};
use tokio::io::AsyncWriteExt;
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
        let tcp_service = TlsAcceptorLayer::new(acceptor_data).layer(
            Forwarder::new(([127, 0, 0, 1], 62800)).connector(
                // ha proxy protocol used to forwarded the client original IP
                HaProxyClientLayer::tcp().layer(TcpConnector::new()),
            ),
        );

        TcpListener::bind("127.0.0.1:63800")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        let tcp_service = (ConsumeErrLayer::default(), HaProxyServerLayer::new())
            .layer(service_fn(internal_tcp_service_fn));

        TcpListener::bind("127.0.0.1:62800")
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

async fn internal_tcp_service_fn<S>(ctx: Context<()>, mut stream: S) -> Result<(), Infallible>
where
    S: Stream + Unpin,
{
    // REMARK: builds on the assumption that we are using the haproxy protocol
    let client_addr = ctx
        .get::<Forwarded>()
        .unwrap()
        .client_socket_addr()
        .unwrap();
    // REMARK: builds on the assumption that rama's TCP service sets this for you :)
    let proxy_addr = ctx.get::<SocketInfo>().unwrap().peer_addr();

    // create the minimal http response
    let payload = format!(
        "hello client {client_addr}, you were served by tls terminator proxy {proxy_addr}\r\n"
    );
    let response = format!(
        "HTTP/1.0 200 ok\r\n\
                            Connection: close\r\n\
                            Content-length: {}\r\n\
                            \r\n\
                            {}",
        payload.len(),
        payload
    );

    stream
        .write_all(response.as_bytes())
        .await
        .expect("write to stream");

    Ok(())
}
