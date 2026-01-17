use rama_core::ServiceInput;
use rama_net::user::credentials::basic;

use super::*;

mod bind;
mod connect;
mod udp;

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_used_failure_unauthorized() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x02")
        // client username-password request
        .read(b"\x01\x03jan\x06secret")
        // server username-password response
        .write(b"\x01\x01")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(basic!("john", "secret").into_authorizer());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_socks5_acceptor_auth_flow_used_failure_unauthorized_missing_password() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x02\x00\x02")
        // server header
        .write(b"\x05\x02")
        // client username-password request
        .read(b"\x01\x04john\x00")
        // server username-password response
        .write(b"\x01\x01")
        .build();

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(Executor::default())
        .with_authorizer(basic!("john", "secret").into_authorizer());
    let result = server.accept(stream).await;
    assert!(result.is_err());
}
