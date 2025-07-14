//! An example to showcase how one can build an authenticated socks5 BIND proxy server.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_bind_proxy --features=dns,socks5
//! ```
//!
//! # Expected output
//!
//! Not many tools in the wild support socks5 bind,
//! and thus this is another self-contained example with the server
//! and client combined.

use rama::{
    Context,
    net::address::SocketAddress,
    net::user::Basic,
    proxy::socks5::{
        Socks5Acceptor, Socks5Client, client::bind::BindOutput, server::DefaultBinder,
    },
    tcp::client::default_tcp_connect,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    let socks5_socket_addr = spawn_socks5_server().await;

    let (proxy_client_stream, _) =
        default_tcp_connect(&Context::default(), socks5_socket_addr.into())
            .await
            .expect("establish connection to socks5 server (from client)");

    let socks5_client = Socks5Client::new().with_auth(Basic::new_static("john", "secret"));

    let binder = socks5_client
        .handshake_bind(proxy_client_stream, None)
        .await
        .expect("initiate socks5 bind handshake");

    let bind_addr = binder.selected_bind_address();

    tokio::spawn(async move {
        // the server application is supposed to do this,
        // after it received the selected bind address from the client
        let (mut stream, _) = default_tcp_connect(&Context::default(), bind_addr.into())
            .await
            .expect("establish connection to socks5 server (from server)");

        tracing::info!("server: read ping via socks5 proxy from client");

        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .expect("server read 'ping'");

        assert_eq!(b"ping", &buf[..]);

        tracing::info!("server: write pong via socks5 proxy to client");

        stream
            .write_all(b"pong")
            .await
            .expect("server write 'pong'");

        // read something that will never come,
        // so we stay blocked until client drops
        let _ = stream.read_u8().await;
    });

    let BindOutput { mut stream, .. } = binder.connect().await.expect("server to be connected");

    tracing::info!("client: write ping via socks5 proxy to server");

    stream
        .write_all(b"ping")
        .await
        .expect("client write 'ping'");

    tracing::info!("client: read pong via socks5 proxy from server");

    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .await
        .expect("client read 'pong'");

    assert_eq!(b"pong", &buf[..]);
    tracing::info!("ping-pong succeeded, bye now!")
}

async fn spawn_socks5_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::local_ipv4(63010))
        .await
        .expect("bind socks5 BIND proxy on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of socks5 proxy server")
        .into();

    let socks5_acceptor = Socks5Acceptor::new()
        .with_authorizer(Basic::new_static("john", "secret").into_authorizer())
        .with_binder(DefaultBinder::default().with_bind_interface(SocketAddress::local_ipv4(0)));

    tokio::spawn(tcp_service.serve(socks5_acceptor));

    bind_addr
}
