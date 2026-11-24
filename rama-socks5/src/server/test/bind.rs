use std::{io, sync::Arc};

use rama_core::{
    ServiceInput,
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef, ExtensionsTransfer},
    io::BridgeIo,
    service::service_fn,
};
use rama_net::address::{HostWithPort, SocketAddress};
use rama_net::stream::{DefaultExtensionsTransfer, NestedConnection};
use rama_net::user::credentials::basic;
use rama_utils::str::non_empty_str;

use crate::server::bind::{Acceptor, MockBinder};
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached());
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached());
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(basic!("john", "secret").into_authorizer());
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(user::Basic::new_insecure(non_empty_str!("john")).into_authorizer());
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_binder(MockBinder::new_err(ReplyKind::ConnectionRefused));
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached()).with_binder(MockBinder::new_bind_err(
        HostWithPort::local_ipv4(3),
        ReplyKind::TtlExpired,
    ));
    let result = server.accept(stream).await;
    result.unwrap_err();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached()).with_binder(MockBinder::new(
        HostWithPort::local_ipv4(5),
        HostWithPort::default_ipv4(0),
    ));
    let result = server.accept(stream).await;
    result.unwrap();
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached()).with_binder(
        MockBinder::new(HostWithPort::local_ipv4(42), HostWithPort::local_ipv4(43))
            .with_proxy_data(
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(basic!("john", "secret").into_authorizer())
        .with_binder(
            MockBinder::new(HostWithPort::local_ipv4(42), HostWithPort::local_ipv4(43))
                .with_proxy_data(
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

    let stream = ServiceInput::new(stream);

    let server = Socks5Acceptor::new(WeakScope::detached())
        .with_authorizer(user::Basic::new_insecure(non_empty_str!("john")).into_authorizer())
        .with_binder(
            MockBinder::new(HostWithPort::local_ipv4(42), HostWithPort::local_ipv4(43))
                .with_proxy_data(
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

#[derive(Debug, Clone, Copy, Extension)]
#[extension(scope(connection))]
struct Socks5ConnFact;

#[derive(Debug, Clone, Copy, Extension)]
struct Socks5FlowFact;

/// Accepts one in-memory connection from 127.0.0.1:43 on 127.0.0.1:42.
struct OneShotAcceptor;

impl Acceptor for OneShotAcceptor {
    type Stream = tokio::io::DuplexStream;

    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(SocketAddress::local_ipv4(42))
    }

    async fn accept(self) -> Result<(Self::Stream, SocketAddress), Error> {
        let (stream, _) = tokio::io::duplex(64);
        Ok((stream, SocketAddress::local_ipv4(43)))
    }
}

async fn bind_tunnel_facts(transfer: impl ExtensionsTransfer) -> (bool, bool) {
    let stream = ServiceInput::new(
        tokio_test::io::Builder::new()
            .read(b"\x05\x01\x00")
            .write(b"\x05\x00")
            .read(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 42])
            .write(&[b'\x05', b'\x00', b'\x00', b'\x01', 127, 0, 0, 1, 0, 43])
            .build(),
    );
    stream.extensions.insert(Socks5ConnFact);
    stream.extensions.insert(Socks5FlowFact);

    let seen = Arc::new(parking_lot::Mutex::new(None));
    let service = service_fn({
        let seen = seen.clone();
        move |BridgeIo(ingress, _incoming): BridgeIo<
            NestedConnection<ServiceInput<tokio_test::io::Mock>>,
            tokio::io::DuplexStream,
        >| {
            let ext: &Extensions = ingress.extensions();
            *seen.lock() = Some((
                ext.contains::<Socks5ConnFact>(),
                ext.contains::<Socks5FlowFact>(),
            ));
            std::future::ready(Ok::<_, BoxError>(()))
        }
    });
    let factory = service_fn(async |_addr: SocketAddress| Ok::<_, BoxError>(OneShotAcceptor));
    let binder = Binder::new(factory, service).with_extensions_transfer(transfer);
    Socks5Acceptor::new(WeakScope::detached())
        .with_binder(binder)
        .accept(stream)
        .await
        .unwrap();
    seen.lock().take().expect("tunnel served")
}

#[tokio::test]
async fn bind_tunnel_keeps_flow_facts_and_drops_connection_facts() {
    assert_eq!(
        bind_tunnel_facts(DefaultExtensionsTransfer::new()).await,
        (false, true)
    );
}

#[tokio::test]
async fn bind_tunnel_custom_transfer_carries_a_chosen_fact() {
    let carry = |outer: &Extensions, nested: &Extensions| {
        if let Some(fact) = outer.get_ref::<Socks5ConnFact>() {
            nested.insert(*fact);
        }
    };
    assert_eq!(
        bind_tunnel_facts(DefaultExtensionsTransfer::new().and(carry)).await,
        (true, true)
    );
}
