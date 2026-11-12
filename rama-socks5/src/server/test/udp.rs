use std::{net::IpAddr, time::Duration};

use crate::server::udp::{DeclaredClientUdpAddressPolicy, MockUdpAssociator};
use crate::server::*;
use rama_core::ServiceInput;
use rama_net::address::{HostWithPort, SocketAddress};
use rama_net::stream::SocketInfo;
use rama_net::user::credentials::basic;
use rama_utils::str::non_empty_str;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_udp_associate_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached());
    let result = server.accept(stream).await;
    result.unwrap_err();
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_declined_udp_associate_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached());
    let result = server.accept(stream).await;
    result.unwrap_err();
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_used_udp_associate_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x02")
        // client username-password request
        .read(b"\x01\x04john\x06secret")
        // server username-password response
        .write(b"\x01\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(basic!("john", "secret").into_authorizer());
    let result = server.accept(stream).await;
    result.unwrap_err();
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_username_only_udp_associate_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x02")
        // client username-password request
        .read(b"\x01\x04john\x00")
        // server username-password response
        .write(b"\x01\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(user::Basic::new_insecure(non_empty_str!("john")).into_authorizer());
    let result = server.accept(stream).await;
    result.unwrap_err();
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_udp_associate_mock_failure() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_udp_associator(MockUdpAssociator::new_err(ReplyKind::ConnectionRefused));
    let result = server.accept(stream).await;
    result.unwrap_err();
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_udp_associate_mock_success_no_data() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_udp_associator(MockUdpAssociator::new(HostWithPort::local_ipv4(42)));
    let result = server.accept(stream).await;
    result.unwrap();
}

/// Send a UDP ASSOCIATE request declaring `192.0.2.1:4660` over a TCP connection from
/// `tcp_peer_ip`, and return the kind of reply the relay gives.
async fn udp_associate_reply_kind(
    policy: DeclaredClientUdpAddressPolicy,
    tcp_peer_ip: Option<IpAddr>,
) -> u8 {
    let (mut client, server_io) = tokio::io::duplex(1024);
    let stream = ServiceInput::new(server_io);
    if let Some(ip) = tcp_peer_ip {
        stream
            .extensions()
            .insert(SocketInfo::new(None, SocketAddress::new(ip, 50000)));
    }

    let server = Socks5Acceptor::new(WeakScope::detached()).with_udp_associator(
        DefaultUdpRelay::default().with_declared_client_udp_address_policy(policy),
    );

    let exchange = async {
        client.write_all(b"\x05\x01\x00").await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        client
            .write_all(b"\x05\x03\x00\x01\xc0\x00\x02\x01\x12\x34")
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        // Closing the TCP stream ends an association the relay accepted.
        drop(client);
        reply[1]
    };

    let (reply_kind, result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exchange, server.accept(stream))
    })
    .await
    .expect("udp associate exchange timeout");
    assert_eq!(
        result.is_ok(),
        reply_kind == u8::from(ReplyKind::Succeeded),
        "{result:?}"
    );
    reply_kind
}

#[tokio::test]
async fn test_socks5_acceptor_udp_associate_declared_address_policy() {
    let declared = IpAddr::from([192, 0, 2, 1]);
    let other = IpAddr::from([192, 0, 2, 2]);
    let succeeded = u8::from(ReplyKind::Succeeded);
    let refused = u8::from(ReplyKind::ConnectionNotAllowed);

    for (policy, tcp_peer_ip, expected) in [
        (
            DeclaredClientUdpAddressPolicy::Trust,
            Some(declared),
            succeeded,
        ),
        (
            DeclaredClientUdpAddressPolicy::Trust,
            Some(other),
            succeeded,
        ),
        (DeclaredClientUdpAddressPolicy::Trust, None, succeeded),
        (
            DeclaredClientUdpAddressPolicy::RequireTcpPeerIp,
            Some(declared),
            succeeded,
        ),
        (
            DeclaredClientUdpAddressPolicy::RequireTcpPeerIp,
            Some(other),
            refused,
        ),
        (
            DeclaredClientUdpAddressPolicy::RequireTcpPeerIp,
            None,
            refused,
        ),
    ] {
        assert_eq!(
            udp_associate_reply_kind(policy, tcp_peer_ip).await,
            expected,
            "policy: {policy:?}, tcp peer: {tcp_peer_ip:?}",
        );
    }
}
