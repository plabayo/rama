use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use rama_udp::test_utils::MemoryDatagramSocket;

use super::*;

/// An HTTP client that must never be asked to open a tunnel.
fn no_client() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(async |_: Request| -> Result<Response, Infallible> {
        panic!("no tunnel may be opened")
    })
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

#[tokio::test]
async fn requests_without_a_masque_tunnel_go_to_the_inner_connector() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector = ConnectUdpConnector::new(
        counting_inner(connections.clone()),
        no_client(),
        Executor::default(),
    );
    for input in [
        request("127.0.0.1:443", None),
        // Addressed to its own MASQUE proxy: dialed as a forward proxy.
        request("127.0.0.1:443", Some("masque://127.0.0.1:443")),
    ] {
        let EstablishedClientConnection { conn, .. } = connector.serve(input).await.unwrap();
        assert!(matches!(conn, MaybeTunneledSocket::Direct(_)), "{conn:?}");
    }
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_route_to_any_other_proxy_is_refused_never_bypassed() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector = ConnectUdpConnector::new(
        counting_inner(connections.clone()),
        no_client(),
        Executor::default(),
    );
    for proxy in ["http://127.0.0.1:8080", "socks5://127.0.0.1:1080"] {
        let error = connector
            .serve(request("192.0.2.1:443", Some(proxy)))
            .await
            .unwrap_err();
        assert!(
            format!("{error:?}").contains("masque proxies only"),
            "{proxy}: {error:?}"
        );
    }
    assert_eq!(connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_tunnel_to_port_zero_is_refused_before_the_proxy_is_asked() {
    let connector = ConnectUdpConnector::new(
        counting_inner(Arc::default()),
        no_client(),
        Executor::default(),
    );
    let error = connector
        .serve(request("192.0.2.1:0", Some("masque://127.0.0.1:443")))
        .await
        .unwrap_err();
    assert!(format!("{error:?}").contains("port is zero"), "{error:?}");
}
