use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use parking_lot::Mutex;
use rama_core::service::service_fn;
use rama_http::Version;
use rama_net::{
    ConnectorTargetInputExt as _, TargetHttpVersionInputExt as _,
    address::{HostWithPort, SocketAddress},
    client::{MaybeProxied, MaybeProxiedConnector, ProxiedRoute},
};
use rama_udp::test_utils::MemoryDatagramSocket;

use super::*;

/// A connector towards proxies that must never be asked for a connection.
fn no_proxy() -> impl ConnectorService<ConnectRequest, Connection = RefusingConnection> {
    service_fn(async |input: ConnectRequest| {
        Err::<EstablishedClientConnection<RefusingConnection, _>, _>(
            ConnectionError::local(
                BoxError::from_static_str("no tunnel may be opened"),
                ConnectionErrorKind::Unavailable,
            )
            .context_field("authority", input.authority),
        )
    })
}

/// A connection to a proxy which never answers; only the request reaching it is asserted.
#[derive(Debug, Clone, ExtensionsRef)]
struct RefusingConnection {
    extensions: Extensions,
}

impl Service<Request> for RefusingConnection {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, _: Request) -> Result<Self::Output, Self::Error> {
        Err(BoxError::from_static_str("proxy connection refused"))
    }
}

/// A datagram connector handing out a memory socket, counting its connections.
fn counting_inner(
    connections: Arc<AtomicUsize>,
) -> impl ConnectorService<ConnectRequest, Connection = MemoryDatagramSocket> {
    service_fn(move |input: ConnectRequest| {
        let connections = connections.clone();
        async move {
            connections.fetch_add(1, Ordering::SeqCst);
            let (conn, _peer) = MemoryDatagramSocket::pair(
                SocketAddress::local_ipv4(4000),
                SocketAddress::local_ipv4(4001),
                NonZeroUsize::MIN,
            );
            Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
        }
    })
}

fn request(target: &str, route: Option<&str>) -> ConnectRequest {
    let request = ConnectRequest::new(HostWithPort::try_from(target).unwrap());
    if let Some(proxy) = route {
        request
            .extensions
            .insert(ProxyRoute::Proxy(ProxyAddress::try_from(proxy).unwrap()));
    }
    request
}

fn maybe_tunneled(
    connections: Arc<AtomicUsize>,
) -> impl ConnectorService<
    ConnectRequest,
    Connection = MaybeProxied<MemoryDatagramSocket, ConnectUdpSocket>,
> {
    MaybeProxiedConnector::new(
        counting_inner(connections),
        HttpConnectUdpProxyConnector::new(no_proxy(), WeakScope::detached()),
        ProxiedRoute,
    )
}

#[tokio::test]
async fn requests_without_a_tunnel_go_to_the_direct_connector() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector = maybe_tunneled(connections.clone());
    let EstablishedClientConnection { conn, .. } = connector
        .connect(request("127.0.0.1:443", None))
        .await
        .unwrap();
    assert!(matches!(conn, MaybeProxied::Direct { .. }), "{conn:?}");
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_route_to_a_proxy_without_connect_udp_is_refused_never_bypassed() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector = maybe_tunneled(connections.clone());
    for proxy in [
        "socks5://127.0.0.1:1080",
        "h3://127.0.0.1:443/ip/{target}/{ipproto}",
    ] {
        let error = connector
            .connect(request("192.0.2.1:443", Some(proxy)))
            .await
            .unwrap_err();
        assert!(
            format!("{error:?}").contains("connect-udp proxies only"),
            "{proxy}: {error:?}"
        );
    }
    assert_eq!(connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_tunnel_to_port_zero_is_refused_before_the_proxy_is_asked() {
    let connector = HttpConnectUdpProxyConnector::new(no_proxy(), WeakScope::detached());
    let error = connector
        .serve(request("192.0.2.1:0", Some("h3://127.0.0.1:443")))
        .await
        .unwrap_err();
    assert!(format!("{error:?}").contains("port is zero"), "{error:?}");
}

#[tokio::test]
async fn a_tunnel_asks_the_proxy_connector_for_the_proxy_in_its_own_version() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = service_fn({
            let seen = seen.clone();
            move |input: ConnectRequest| {
                seen.lock()
                    .push((input.connector_target(), input.target_http_version()));
                async move {
                    Err::<EstablishedClientConnection<RefusingConnection, _>, _>(
                        ConnectionError::local(
                            BoxError::from_static_str("proxy unreachable"),
                            ConnectionErrorKind::Unavailable,
                        ),
                    )
                }
            }
        });
        let connector = HttpConnectUdpProxyConnector::new(proxy, WeakScope::detached());

        let input = request("example.com:443", None);
        input.extensions.insert(ProxyRoute::Proxy(
            ProxyAddress::try_from("h3://proxy.example:443")
                .unwrap()
                .with_http_version(version),
        ));
        let error = connector.serve(input).await.unwrap_err();

        assert!(
            format!("{error:?}").contains("proxy unreachable"),
            "{version:?}: {error:?}"
        );
        assert_eq!(
            *seen.lock(),
            [(
                Some(HostWithPort::try_from("proxy.example:443").unwrap()),
                Some(version)
            )],
            "{version:?}"
        );
    }
}
