use rama::{
    extensions::Extensions, net::address::SocketAddress, tcp::client::default_tcp_connect,
    telemetry::tracing, udp::UdpSocket,
};

#[cfg(feature = "boring")]
use ::{
    rama::{
        net::client::{ConnectorService, EstablishedClientConnection},
        net::tls::client::ServerVerifyMode,
        tcp::client::{Request as TcpRequest, service::TcpConnector},
        tls::boring::client::{TlsConnector, TlsConnectorDataBuilder},
    },
    std::sync::Arc,
};

use super::utils;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
#[ignore]
async fn test_tcp_discard() {
    utils::init_tracing();

    let _guard = utils::RamaService::discard(63114, "tcp");

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(&extensions, ([127, 0, 0, 1], 63114).into()).await {
            Ok((s, _)) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                tracing::error!("connect_tcp error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }
    let mut stream = stream.expect("connect to tcp listener");

    let mut buf = [0; 1];

    stream.write_all(b"hello").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), stream.read(&mut buf))
            .await
            .is_err()
    );

    stream.write_all(b"world").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), stream.read(&mut buf))
            .await
            .is_err()
    );
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_tls_tcp_discard() {
    utils::init_tracing();

    let _guard = utils::RamaService::discard(63115, "tls");

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        let connector = TlsConnector::secure(TcpConnector::new()).with_connector_data(Arc::new(
            TlsConnectorDataBuilder::new().with_server_verify_mode(ServerVerifyMode::Disable),
        ));
        match connector
            .connect(TcpRequest::new(([127, 0, 0, 1], 63115).into(), extensions))
            .await
        {
            Ok(EstablishedClientConnection { conn, .. }) => {
                stream = Some(conn);
                break;
            }
            Err(e) => {
                tracing::error!("tls(tcp) connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }
    let mut stream = stream.expect("connect to tls-tcp listener");

    let mut buf = [0; 1];

    stream.write_all(b"hello").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), stream.read(&mut buf))
            .await
            .is_err()
    );

    stream.write_all(b"world").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), stream.read(&mut buf))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore]
async fn test_udp_discard() {
    utils::init_tracing();

    let _guard = utils::RamaService::discard(63116, "udp");
    let socket = UdpSocket::bind(SocketAddress::local_ipv4(63117))
        .await
        .unwrap();

    for i in 0..5 {
        match socket.connect(SocketAddress::local_ipv4(63116)).await {
            Ok(_) => break,
            Err(e) => {
                tracing::error!("UdpSocket::connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }

    let mut buf = [0; 1];

    socket.send(b"hello").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), socket.recv(&mut buf))
            .await
            .is_err()
    );

    socket.send(b"world").await.unwrap();
    // nothing is ever to be received!
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), socket.recv(&mut buf))
            .await
            .is_err()
    );
}
