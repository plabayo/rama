use crate::server::udp::MockUdpAssociator;
use crate::server::*;
use rama_net::address::Authority;

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

    let server = Socks5Acceptor::new();
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
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

    let server = Socks5Acceptor::new();
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
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

    let server = Socks5Acceptor::new().with_auth(Socks5Auth::username_password("john", "secret"));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
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

    let server = Socks5Acceptor::new().with_auth(Socks5Auth::username("john"));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
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

    let server = Socks5Acceptor::new()
        .with_udp_associator(MockUdpAssociator::new_err(ReplyKind::ConnectionRefused));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
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

    let server = Socks5Acceptor::new()
        .with_udp_associator(MockUdpAssociator::new(Authority::local_ipv4(42)));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_ok());
}
