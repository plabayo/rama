use rama_core::ServiceInput;
use rama_net::user::credentials::basic;

use super::*;

mod bind;
mod connect;
mod udp;

#[tokio::test(start_paused = true)]
async fn test_socks5_acceptor_handshake_timeout_aborts_stalled_client() {
    let (server_io, _client_io) = tokio::io::duplex(1024);

    let server = Socks5Acceptor::new(Executor::default())
        .with_handshake_timeout(std::time::Duration::from_secs(5));
    let err = server
        .accept(ServiceInput::new(server_io))
        .await
        .expect_err("a client that never sends its greeting must not be waited on forever");
    assert!(
        err.to_string().contains("socks5 handshake timeout"),
        "expected a handshake timeout abort, got: {err}"
    );
}

#[tokio::test(start_paused = true)]
async fn test_socks5_acceptor_handshake_timeout_spans_whole_handshake() {
    use tokio::io::AsyncWriteExt as _;

    let (server_io, mut client_io) = tokio::io::duplex(1024);

    // Each step on its own stays inside the 5s budget, but together they exceed
    // it: a per-read timeout would let this through, a handshake-wide one must not.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if client_io.write_all(b"\x05\x01\x00").await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // By now the server has given up, so this write is expected to fail.
        let _late_write = client_io
            .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
            .await;
    });

    let server = Socks5Acceptor::new(Executor::default())
        .with_handshake_timeout(std::time::Duration::from_secs(5));
    let err = server
        .accept(ServiceInput::new(server_io))
        .await
        .expect_err("the handshake budget must cover every step together");
    assert!(
        err.to_string().contains("socks5 handshake timeout"),
        "expected a handshake timeout abort, got: {err}"
    );
}

#[tokio::test(start_paused = true)]
async fn test_socks5_acceptor_without_handshake_timeout_waits() {
    let (server_io, _client_io) = tokio::io::duplex(1024);

    // No handshake timeout configured: the stalled handshake must still be pending
    // after an hour of (virtual) time, i.e. nothing times it out behind our back.
    let server = Socks5Acceptor::new(Executor::default());
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        server.accept(ServiceInput::new(server_io)),
    )
    .await;
    assert!(
        result.is_err(),
        "without a handshake timeout the handshake must not complete on its own"
    );
}

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
