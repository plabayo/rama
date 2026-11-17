use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rama_core::{Fork as _, extensions::Extension, service::service_fn};
use rama_net::{address::SocketAddress, stream::Socket as _};
use tokio::time::timeout;

use super::*;
use crate::{
    DatagramFeature, DatagramSenderExt as _, DatagramSocketExt as _, SendDatagram,
    proxy::{DatagramForwardService, EcnPolicy},
    test_utils::MemoryDatagramSocket,
};

const LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Extension)]
struct Marker;

/// Client ⇄ ingress.
fn association() -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(6000),
        SocketAddress::local_ipv4(6001),
        NonZeroUsize::new(8).unwrap(),
    )
}

#[tokio::test]
async fn the_udp_connector_bridges_to_the_static_target() {
    timeout(LIMIT, async {
        let mut origin = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let target = origin.local_addr().unwrap();
        let (_client, ingress) = association();
        let bridge = DatagramToProxyBridge::new(
            service_fn(
                move |BridgeIo(_ingress, egress): BridgeIo<_, UdpPacketSocket>| async move {
                    assert_eq!(egress.peer_addr().unwrap(), target);
                    egress
                        .create_sender()
                        .send(SendDatagram::new(target, b"from egress"))
                        .await
                        .unwrap();
                    Ok::<_, BoxError>(())
                },
            ),
            target,
        );
        bridge.serve(ingress).await.unwrap();
        let mut buffer = [0; 64];
        let metadata = origin.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"from egress");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_udp_connector_refuses_a_name_it_would_have_to_resolve() {
    let (_client, ingress) = association();
    let error = DatagramToProxyBridge::new(
        service_fn(
            async |_: BridgeIo<MemoryDatagramSocket, UdpPacketSocket>| Ok::<_, BoxError>(()),
        ),
        HostWithPort::try_from("example.com:443").unwrap(),
    )
    .serve(ingress)
    .await
    .unwrap_err();
    assert!(format!("{error:?}").contains("not an IP"), "{error:?}");
}

#[tokio::test]
async fn the_udp_connector_dials_the_connector_target_over_the_authority() {
    let origin = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let target = origin.local_addr().unwrap();
    let request = ConnectRequest::new(HostWithPort::try_from("example.com:443").unwrap());
    request
        .extensions
        .insert(ConnectorTarget(HostWithPort::from(target)));
    let EstablishedClientConnection { conn, .. } =
        UdpConnector::new().serve(request).await.unwrap();
    assert_eq!(conn.peer_addr().unwrap(), target);
}

/// A connector that hands out the memory socket it holds, recording what it was asked.
#[derive(Clone)]
struct MemoryConnector {
    egress: Arc<parking_lot::Mutex<Option<MemoryDatagramSocket>>>,
    saw_marker: Arc<AtomicBool>,
}

impl Service<ConnectRequest> for MemoryConnector {
    type Output = EstablishedClientConnection<MemoryDatagramSocket, ConnectRequest>;
    type Error = Infallible;

    async fn serve(&self, request: ConnectRequest) -> Result<Self::Output, Self::Error> {
        assert_eq!(request.authority, HostWithPort::local_ipv4(7001));
        self.saw_marker
            .store(request.extensions.contains::<Marker>(), Ordering::Relaxed);
        Ok(EstablishedClientConnection {
            conn: self.egress.lock().take().unwrap(),
            input: request,
        })
    }
}

#[tokio::test]
async fn a_custom_connector_gets_the_extension_target_and_the_associations_extensions() {
    timeout(LIMIT, async {
        let (egress, _origin) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(7000),
            SocketAddress::local_ipv4(7001),
            NonZeroUsize::new(8).unwrap(),
        );
        let saw_marker = Arc::new(AtomicBool::new(false));
        let layer = DatagramToProxyBridgeLayer::extension_connector_target().with_connector(
            MemoryConnector {
                egress: Arc::new(parking_lot::Mutex::new(Some(egress))),
                saw_marker: saw_marker.clone(),
            },
        );
        let bridge = layer.into_layer(service_fn(
            async |BridgeIo(_, egress): BridgeIo<MemoryDatagramSocket, MemoryDatagramSocket>| {
                Ok::<_, BoxError>(egress.peer_addr().unwrap())
            },
        ));
        let (_client, ingress) = association();
        // Without a target in its extensions, the association fails.
        bridge.serve(ingress).await.unwrap_err();
        let (_client, ingress) = association();
        ingress
            .extensions()
            .insert(ConnectorTarget(HostWithPort::local_ipv4(7001)));
        ingress.extensions().insert(Marker);
        assert_eq!(
            bridge.serve(ingress).await.unwrap(),
            SocketAddress::local_ipv4(7001)
        );
        assert!(saw_marker.load(Ordering::Relaxed));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn forwarding_takes_a_bridge_of_connected_sockets() {
    timeout(LIMIT, async {
        let (client, ingress) = association();
        let (egress, mut origin) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(7000),
            SocketAddress::local_ipv4(7001),
            NonZeroUsize::new(8).unwrap(),
        );
        let forward =
            DatagramForwardService::new(NonZeroUsize::new(64).unwrap(), EcnPolicy::Discard);
        let forwarding =
            tokio::spawn(async move { forward.serve(BridgeIo(ingress, egress)).await });
        client
            .create_sender()
            .send(SendDatagram::new(
                SocketAddress::local_ipv4(6001),
                b"through",
            ))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let metadata = origin.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"through");
        forwarding.abort();
        let _cancelled = forwarding.await;
    })
    .await
    .unwrap();
}

/// What a connector produced for a replacement: refused, or a socket with or without `feature`.
fn outcome(
    result: Result<EstablishedClientConnection<UdpPacketSocket, ConnectRequest>, BoxError>,
    feature: DatagramFeature,
) -> Option<bool> {
    result
        .ok()
        .map(|connected| connected.conn.capabilities().supports(feature))
}

/// Building a replacement with a fresh default connector and a clone of the request drops the
/// configuration of the connector that made the original egress.
#[tokio::test]
async fn a_fresh_default_connector_loses_the_original_connector_configuration() {
    let origin = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let request = ConnectRequest::new(origin.local_addr().unwrap().into());
    let feature = DatagramFeature::ReceiveOriginalDestination;
    let configured =
        UdpConnector::new().with_config(UdpSocketConfig::new().with_required_feature(feature));

    let original = outcome(configured.serve(request.fork()).await, feature);
    let hand_built = outcome(UdpConnector::new().serve(request.clone()).await, feature);
    assert_eq!(
        hand_built,
        Some(false),
        "a default socket lacks the feature"
    );
    assert_ne!(
        hand_built, original,
        "the configured connector either provides the feature or refuses"
    );

    let replacement = DatagramReplacementConnector::new(configured, request)
        .serve(())
        .await;
    assert_eq!(
        replacement
            .ok()
            .map(|socket| socket.capabilities().supports(feature)),
        original,
        "the replacement connector keeps the configuration"
    );
}

/// Records whether a request already carried a [`Marker`] and then marks it, as a connector
/// annotating its request does.
#[derive(Clone)]
struct MarkingConnector {
    saw_marker: Arc<AtomicBool>,
}

impl Service<ConnectRequest> for MarkingConnector {
    type Output = EstablishedClientConnection<UdpPacketSocket, ConnectRequest>;
    type Error = BoxError;

    async fn serve(&self, request: ConnectRequest) -> Result<Self::Output, Self::Error> {
        self.saw_marker
            .store(request.extensions.contains::<Marker>(), Ordering::Relaxed);
        request.extensions.insert(Marker);
        UdpConnector::new().serve(request).await
    }
}

/// A cloned request shares its extensions, so one replacement attempt leaks into the next;
/// the replacement connector forks them per attempt.
#[tokio::test]
async fn replacement_attempts_do_not_share_request_extensions() {
    let origin = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let request = ConnectRequest::new(origin.local_addr().unwrap().into());
    let saw_marker = Arc::new(AtomicBool::new(false));
    let connector = MarkingConnector {
        saw_marker: saw_marker.clone(),
    };

    for _ in 0..2 {
        connector.serve(request.clone()).await.unwrap();
    }
    assert!(
        saw_marker.load(Ordering::Relaxed),
        "a cloned request carries the previous attempt's extensions"
    );

    let request = ConnectRequest::new(origin.local_addr().unwrap().into());
    let replacement = DatagramReplacementConnector::new(connector, request.clone());
    for _ in 0..2 {
        replacement.serve(()).await.unwrap();
        assert!(!saw_marker.load(Ordering::Relaxed));
    }
    assert!(!request.extensions.contains::<Marker>());
}

/// The connector creates its socket with the configured socket options.
#[cfg(any(
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "linux",
    target_os = "android",
))]
#[tokio::test]
async fn the_udp_connector_applies_configured_socket_options() {
    let loopback = rama_net::socket::interfaces()
        .unwrap()
        .into_iter()
        .find(|iface| {
            iface
                .flags()
                .contains(rama_net::socket::InterfaceFlags::LOOPBACK)
        })
        .and_then(|iface| iface.index())
        .and_then(core::num::NonZeroU32::new)
        .unwrap();
    let origin = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let options = rama_net::socket::SocketOptions {
        interface_index: Some(loopback),
        ..rama_net::socket::SocketOptions::default_udp()
    };
    let connected = UdpConnector::new()
        .with_config(UdpSocketConfig::new().with_socket_options(options))
        .serve(ConnectRequest::new(origin.local_addr().unwrap().into()))
        .await
        .unwrap();
    assert_eq!(
        connected.conn.socket_ref().device_index_v4().unwrap(),
        Some(loopback)
    );
    assert_eq!(
        connected.conn.peer_addr().unwrap(),
        origin.local_addr().unwrap()
    );
}
