use rama_core::{
    Layer, ServiceInput,
    error::BoxError,
    extensions::ExtensionsRef,
    io::{BridgeIo, rewind::Rewind},
    layer::TimeoutLayer,
    service::service_fn,
};
use rama_net::user::credentials::basic;
use rama_net::{
    address::{HostWithPort, SocketAddress},
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorTarget,
        EstablishedClientConnection,
    },
    proxy::IoForwardService,
    stream::SocketInfo,
    test_utils::client::MockSocket,
};
use rama_utils::str::non_empty_str;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use crate::server::connect::MockConnector;
use crate::server::*;

async fn assert_eager_connector_metadata(
    request: &[u8],
    destination: HostWithPort,
    socket_info: Option<SocketInfo>,
    hide_local_address: bool,
    reply: &[u8],
) {
    let mut stream = tokio_test::io::Builder::new();
    stream
        .read(b"\x05\x01\x00")
        .write(b"\x05\x00")
        .read(request)
        .write(reply);

    let connector_target_seen = Arc::new(AtomicBool::new(false));
    let connector = service_fn({
        let destination = destination.clone();
        let connector_target_seen = connector_target_seen.clone();
        move |request: ConnectRequest| {
            assert_eq!(
                request.extensions.get_ref::<ConnectorTarget>(),
                Some(&ConnectorTarget(destination.clone()))
            );
            connector_target_seen.store(true, Ordering::SeqCst);

            // Connector-local routing must not overwrite the authoritative
            // SOCKS target exposed through the ingress stream.
            request
                .extensions
                .insert(ConnectorTarget(HostWithPort::local_ipv4(9)));

            let (stream, _) = tokio::io::duplex(64);
            let stream = MockSocket::new(stream);
            if let Some(socket_info) = socket_info.clone() {
                stream.extensions().insert(socket_info);
            }
            std::future::ready(Ok::<_, ConnectionError>(EstablishedClientConnection {
                input: request,
                conn: Rewind::new_buffered(stream, Default::default()),
            }))
        }
    });

    let bridge_target_seen = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let destination = destination.clone();
        let bridge_target_seen = bridge_target_seen.clone();
        move |bridge: BridgeIo<ServiceInput<tokio_test::io::Mock>, Rewind<MockSocket>>| {
            assert_eq!(
                bridge.extensions().get_ref::<ConnectorTarget>(),
                Some(&ConnectorTarget(destination.clone()))
            );
            bridge_target_seen.store(true, Ordering::SeqCst);
            std::future::ready(Ok::<_, BoxError>(()))
        }
    });

    let connector = Connector::new(connector, service).with_hide_local_address(hide_local_address);
    let server = Socks5Acceptor::new(Executor::default()).with_connector(connector);

    server
        .accept(ServiceInput::new(stream.build()))
        .await
        .unwrap();
    assert!(connector_target_seen.load(Ordering::SeqCst));
    assert!(bridge_target_seen.load(Ordering::SeqCst));
}

#[test]
fn socks5_acceptor_default_uses_connector() {
    let _: Socks5Acceptor<DefaultConnector> = Socks5Acceptor::default();
}

#[tokio::test]
async fn eager_connector_uses_socket_info_and_propagates_requested_target() {
    let cases = [
        (
            b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90".as_slice(),
            HostWithPort::local_ipv4(8080),
        ),
        (
            b"\x05\x01\x00\x03\x0bexample.com\x01\xbb".as_slice(),
            HostWithPort::example_domain_https(),
        ),
        (
            b"\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f\x90"
                .as_slice(),
            HostWithPort::local_ipv6(8080),
        ),
    ];

    for (request, destination) in cases {
        assert_eager_connector_metadata(
            request,
            destination,
            Some(SocketInfo::new(
                Some(SocketAddress::local_ipv4(42)),
                SocketAddress::local_ipv4(8080),
            )),
            false,
            b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x2a",
        )
        .await;
    }
}

#[tokio::test]
async fn eager_connector_hides_or_defaults_missing_local_socket_info() {
    let request = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90";
    let destination = HostWithPort::local_ipv4(8080);
    let default_reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";

    assert_eager_connector_metadata(
        request,
        destination.clone(),
        Some(SocketInfo::new(
            Some(SocketAddress::local_ipv4(42)),
            SocketAddress::local_ipv4(8080),
        )),
        true,
        default_reply,
    )
    .await;

    assert_eager_connector_metadata(request, destination, None, false, default_reply).await;
}

#[tokio::test]
async fn connector_reports_egress_failure_during_handshake() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client CONNECT request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // egress failure reply: never acknowledge the CONNECT request
        .write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let attempted = Arc::new(AtomicBool::new(false));
    let connector = service_fn({
        let attempted = attempted.clone();
        move |_req: ConnectRequest| {
            attempted.store(true, Ordering::SeqCst);
            std::future::ready(Err::<
                EstablishedClientConnection<MockSocket, ConnectRequest>,
                _,
            >(ConnectionError::transport(
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "egress refused"),
                ConnectionErrorKind::Unavailable,
            )))
        }
    });
    let server = Socks5Acceptor::new(Executor::default())
        .with_connector(Connector::new(connector, IoForwardService::default()));

    server.accept(ServiceInput::new(stream)).await.unwrap_err();
    assert!(attempted.load(Ordering::SeqCst));
}

#[tokio::test]
async fn connector_timeout_layer_reports_ttl_expired_during_handshake() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client CONNECT request
        .read(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        // timeout reply
        .write(b"\x05\x06\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let connector = service_fn(|_req: ConnectRequest| async move {
        std::future::pending::<
            Result<EstablishedClientConnection<MockSocket, ConnectRequest>, ConnectionError>,
        >()
        .await
    });
    let connector = TimeoutLayer::new(Duration::ZERO).into_layer(connector);
    let server = Socks5Acceptor::new(Executor::default())
        .with_connector(Connector::new(connector, IoForwardService::default()));

    server.accept(ServiceInput::new(stream)).await.unwrap_err();
}

#[tokio::test]
async fn lazy_connector_remains_an_explicit_opt_in() {
    let stream = tokio_test::io::Builder::new()
        // client header
        .read(b"\x05\x01\x00")
        // server header
        .write(b"\x05\x00")
        // client CONNECT request
        .read(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90")
        // lazy mode acknowledges before delegating
        .write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        .build();

    let delegated = Arc::new(AtomicBool::new(false));
    let lazy = LazyConnector::new(service_fn({
        let delegated = delegated.clone();
        move |stream: ServiceInput<tokio_test::io::Mock>| {
            assert_eq!(
                stream.extensions().get_ref::<ConnectorTarget>(),
                Some(&ConnectorTarget(HostWithPort::local_ipv4(8080)))
            );
            delegated.store(true, Ordering::SeqCst);
            std::future::ready(Ok::<_, BoxError>(()))
        }
    }));
    let server = Socks5Acceptor::new(Executor::default()).with_connector(lazy);

    server.accept(ServiceInput::new(stream)).await.unwrap();
    assert!(delegated.load(Ordering::SeqCst));
}

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
    result.unwrap_err();
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
    result.unwrap_err();
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
    result.unwrap_err();
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
    result.unwrap_err();
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
    result.unwrap_err();
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
    result.unwrap();
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
    result.unwrap();
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
    result.unwrap();
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
    result.unwrap();
}
