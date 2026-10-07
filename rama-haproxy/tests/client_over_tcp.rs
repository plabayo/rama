//! The PROXY client layer over a real TCP connector, which records its own outbound
//! [`SocketInfo`] on the connection: the header still names the original client.

#![allow(clippy::unwrap_used)]

use rama_core::{Layer, Service, extensions::ExtensionsRef as _};
use rama_haproxy::client::HaProxyLayer;
use rama_net::{
    client::ConnectRequest,
    forwarded::{Forwarded, ForwardedElement, NodeId},
    stream::SocketInfo,
};
use rama_tcp::client::service::TcpConnector;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader},
    net::TcpListener,
};

const CLIENT: &str = "127.0.1.2:54321";

async fn origin() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn request(port: u16) -> ConnectRequest {
    let request = ConnectRequest::new(format!("127.0.0.1:{port}").parse().unwrap());
    request
        .extensions()
        .insert(SocketInfo::new(None, CLIENT.parse().unwrap()));
    request
}

#[tokio::test]
async fn v1_names_the_original_client() {
    let (listener, port) = origin().await;
    let established = HaProxyLayer::tcp()
        .v1()
        .layer(TcpConnector::new())
        .serve(request(port))
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let mut line = String::new();
    BufReader::new(socket).read_line(&mut line).await.unwrap();
    assert_eq!(
        line,
        format!("PROXY TCP4 127.0.1.2 127.0.0.1 54321 {port}\r\n")
    );
    drop(established);
}

#[tokio::test]
async fn v2_names_the_original_client() {
    let (listener, port) = origin().await;
    let established = HaProxyLayer::tcp()
        .layer(TcpConnector::new())
        .serve(request(port))
        .await
        .unwrap();
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut header = [0; 28];
    socket.read_exact(&mut header).await.unwrap();
    let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    expected.extend_from_slice(&[0x21, 0x11, 0, 12, 127, 0, 1, 2, 127, 0, 0, 1]);
    expected.extend_from_slice(&54321u16.to_be_bytes());
    expected.extend_from_slice(&port.to_be_bytes());
    assert_eq!(header.as_slice(), expected.as_slice());
    drop(established);
}

/// A [`Forwarded`] client still wins over the input's own peer.
#[tokio::test]
async fn a_forwarded_client_wins_over_the_inputs_peer() {
    let (listener, port) = origin().await;
    let request = request(port);
    request
        .extensions()
        .insert(Forwarded::new(ForwardedElement::new_forwarded_for(
            NodeId::try_from("127.0.3.4:8080").unwrap(),
        )));
    let established = HaProxyLayer::tcp()
        .v1()
        .layer(TcpConnector::new())
        .serve(request)
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let mut line = String::new();
    BufReader::new(socket).read_line(&mut line).await.unwrap();
    assert_eq!(
        line,
        format!("PROXY TCP4 127.0.3.4 127.0.0.1 8080 {port}\r\n")
    );
    drop(established);
}
