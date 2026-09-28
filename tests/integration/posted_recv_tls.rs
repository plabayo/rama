//! A boring TLS client over a [`PostedRecv`] TCP stream: the handshake and
//! reads work through the wrapper, and a reply the server sends right before
//! resetting still reaches the client.

use std::{convert::Infallible, time::Duration};

use rama::{
    Layer, Service,
    net::client::{ConnectRequest, EstablishedClientConnection},
    service::service_fn,
    tcp::{
        TcpStream,
        client::service::TcpConnector,
        posted_recv::{PostedRecv, PostedRecvLayer},
    },
    tls::{
        boring::{TlsStream, client::TlsConnectorLayer, server::TlsAcceptorLayer},
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
};
use rama_tls::client::ServerVerifyMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST: &[u8] = b"PING\r\n";

fn reply(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Serve TLS on a loopback port; each connection gets `reply(len)` and is
/// then closed with `close_notify`, or reset when `reset` is set.
async fn spawn_tls_origin(len: usize, reset: bool) -> std::net::SocketAddr {
    let config = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self-signed");
    let acceptor = TlsAcceptorLayer::new(config).into_layer(service_fn(
        move |mut stream: TlsStream<TcpStream>| async move {
            let mut req = vec![0; REQUEST.len()];
            stream.read_exact(&mut req).await.unwrap();
            stream.write_all(&reply(len)).await.unwrap();
            stream.flush().await.unwrap();
            if reset {
                tokio::time::sleep(Duration::from_millis(50)).await;
            } else {
                stream.shutdown().await.unwrap();
            }
            Ok::<_, Infallible>(())
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            if reset {
                // Dropping the TLS stream without close_notify then resets.
                stream.set_zero_linger().unwrap();
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                _ = acceptor.serve(TcpStream::new(stream)).await;
            });
        }
    });
    addr
}

async fn connect(addr: std::net::SocketAddr) -> TlsStream<PostedRecv<TcpStream>> {
    let connector = TlsConnectorLayer::secure()
        .with_base_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable))
        .into_layer(PostedRecvLayer::new().into_layer(TcpConnector::new()));
    let EstablishedClientConnection { conn, .. } = connector
        .serve(ConnectRequest::new(addr.into()))
        .await
        .unwrap();
    conn
}

async fn read_until_end<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> (Vec<u8>, std::io::Result<()>) {
    let mut bytes = Vec::new();
    let mut buf = vec![0; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return (bytes, Ok(())),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(err) => return (bytes, Err(err)),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_over_posted_recv_reads_to_end() {
    for len in [234, 6554, 200 * 1024] {
        let addr = spawn_tls_origin(len, false).await;
        let mut stream = connect(addr).await;
        stream.write_all(REQUEST).await.unwrap();
        let (bytes, end) = read_until_end(&mut stream).await;
        assert_eq!(bytes, reply(len), "N={len}");
        end.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_over_posted_recv_keeps_reply_before_reset() {
    for len in [234, 6554] {
        let addr = spawn_tls_origin(len, true).await;
        for _ in 0..20 {
            let mut stream = connect(addr).await;
            stream.write_all(REQUEST).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (bytes, end) = read_until_end(&mut stream).await;
            assert_eq!(bytes, reply(len), "N={len}");
            assert!(
                end.is_err(),
                "a reset without close_notify must not look clean"
            );
        }
    }
}
