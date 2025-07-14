use rama_net::address::Authority;

use crate::server::bind::MockBinder;
use crate::server::*;

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_bind_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server = Socks5Acceptor::new();
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_declined_bind_failure_method_not_supported() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server = Socks5Acceptor::new();
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_used_bind_failure_method_not_supported() {
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
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server = Socks5Acceptor::new()
        .with_authorizer(user::Basic::new_static("john", "secret").into_authorizer());
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_username_only_bind_failure_method_not_supported() {
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
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server = Socks5Acceptor::new()
        .with_authorizer(user::Basic::new_static_insecure("john").into_authorizer());
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_bind_mock_failure() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server =
        Socks5Acceptor::new().with_binder(MockBinder::new_err(ReplyKind::ConnectionRefused));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_bind_mock_failure_on_second_reply() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 3])
        .write(b"\x05\x06\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let server = Socks5Acceptor::new().with_binder(MockBinder::new_bind_err(
        Authority::local_ipv4(3),
        ReplyKind::TtlExpired,
    ));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_bind_mock_success_no_data() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 5])
        // 2nd server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 0, 0, 0, 0, 0, 0])
        .build();

    let server = Socks5Acceptor::new().with_binder(MockBinder::new(
        Authority::local_ipv4(5),
        Authority::default_ipv4(0),
    ));
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_no_auth_client_default_bind_mock_success_with_data() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client request
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // 2nd server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 43])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let server = Socks5Acceptor::new().with_binder(
        MockBinder::new(Authority::local_ipv4(42), Authority::local_ipv4(43)).with_proxy_data(
            tokio_test::io::Builder::new()
                // client data
                .write(b"ping")
                // server data
                .read(b"pong")
                .build(),
        ),
    );
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_with_auth_flow_client_bind_mock_success_with_data() {
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
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // 2nd server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 43])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let server = Socks5Acceptor::new()
        .with_authorizer(user::Basic::new_static("john", "secret").into_authorizer())
        .with_binder(
            MockBinder::new(Authority::local_ipv4(42), Authority::local_ipv4(43)).with_proxy_data(
                tokio_test::io::Builder::new()
                    // client data
                    .write(b"ping")
                    // server data
                    .read(b"pong")
                    .build(),
            ),
        );
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_socks5_acceptor_with_auth_flow_username_only_client_bind_mock_success_with_data() {
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
        .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        // server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
        // 2nd server reply
        .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 43])
        // client data
        .read(b"ping")
        // server data
        .write(b"pong")
        .build();

    let server = Socks5Acceptor::new()
        .with_authorizer(user::Basic::new_static_insecure("john").into_authorizer())
        .with_binder(
            MockBinder::new(Authority::local_ipv4(42), Authority::local_ipv4(43)).with_proxy_data(
                tokio_test::io::Builder::new()
                    // client data
                    .write(b"ping")
                    // server data
                    .read(b"pong")
                    .build(),
            ),
        );
    let result = server.accept(Context::default(), stream).await;
    assert!(result.is_ok());
}
