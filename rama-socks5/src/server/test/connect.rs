use rama_core::ServiceInput;
use rama_net::address::HostWithPort;
use rama_net::user::credentials::basic;
use rama_utils::str::non_empty_str;

use crate::server::connect::MockConnector;
use crate::server::*;

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_connect_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_declined_connect_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_used_connect_failure_method_not_supported() {
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
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(basic!("john", "secret").into_authorizer());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_username_only_connect_failure_method_not_supported() {
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
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(user::Basic::new_insecure(non_empty_str!("john")).into_authorizer());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_connect_mock_failure() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_connector(MockConnector::new_err(ReplyKind::ConnectionRefused));
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_connect_mock_success_no_data() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_connector(MockConnector::new(HostWithPort::local_ipv4(42)));
    let result = server.accept(stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_connect_mock_success_with_data() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default()).with_connector(
        MockConnector::new(HostWithPort::local_ipv4(42)).with_proxy_data(
            tokio_test::io::Builder::new()
                // client data
                .write(b"ping")
                // server data
                .read(b"pong")
                .build(),
        ),
    );
    let result = server.accept(stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_with_auth_flow_client_connect_mock_success_with_data() {
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
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(basic!("john", "secret").into_authorizer())
        .with_connector(
            MockConnector::new(HostWithPort::local_ipv4(42)).with_proxy_data(
                tokio_test::io::Builder::new()
                    // client data
                    .write(b"ping")
                    // server data
                    .read(b"pong")
                    .build(),
            ),
        );
    let result = server.accept(stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_with_auth_flow_username_only_client_connect_mock_success_with_data() {
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
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(user::Basic::new_insecure(non_empty_str!("john")).into_authorizer())
        .with_connector(
            MockConnector::new(HostWithPort::local_ipv4(42)).with_proxy_data(
                tokio_test::io::Builder::new()
                    // client data
                    .write(b"ping")
                    // server data
                    .read(b"pong")
                    .build(),
            ),
        );
    let result = server.accept(stream).await;
    assert!(result.is_ok());
}
