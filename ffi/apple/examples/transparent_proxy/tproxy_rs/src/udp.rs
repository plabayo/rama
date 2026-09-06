use std::{cell::RefCell, convert::Infallible, io, net::SocketAddr};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    net::{
        apple::networkextension::{Datagram, UdpFlow, tproxy::TransparentProxyServiceContext},
        client::ConnectorTarget,
    },
    service::service_fn,
    telemetry::tracing,
    udp::{UdpSocket, bind_udp_with_address},
    utils::octets::kib,
};

#[cfg(any(test, feature = "e2e"))]
use rama::bytes::Bytes;
#[cfg(any(test, feature = "e2e"))]
use rama::net::apple::networkextension::tproxy::{
    DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES, TransparentProxyFlowMeta,
};
#[cfg(any(test, feature = "e2e"))]
use std::time::Duration;

use super::UdpPolicyScope;

#[cfg(any(test, feature = "e2e"))]
const E2E_PRESSURE_MARKER: &[u8] = b"rama-udp-e2e-pressure-v1 ";
#[cfg(any(test, feature = "e2e"))]
const E2E_PRESSURE_MAX_RETAINED_ITEMS: usize = 4_096;
const UDP_RECV_SCRATCH_LEN: usize = kib(64);

thread_local! {
    /// One receive allocation per runtime worker that actually receives UDP.
    ///
    /// The `RefCell` is borrowed only around `try_recv_from` and the exact-size
    /// `Bytes` copy. In particular, its borrow never crosses an `.await`, so a
    /// Tokio task remains free to move between workers while it is suspended.
    static UDP_RECV_SCRATCH: RefCell<Option<UdpRecvScratch>> = const { RefCell::new(None) };
}

struct UdpRecvScratch {
    bytes: Box<[u8]>,
}

impl UdpRecvScratch {
    fn new() -> Self {
        #[cfg(test)]
        {
            let active = UDP_RECV_SCRATCH_ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
            UDP_RECV_SCRATCH_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            UDP_RECV_SCRATCH_PEAK.fetch_max(active, Ordering::Relaxed);
        }

        Self {
            bytes: vec![0; UDP_RECV_SCRATCH_LEN].into_boxed_slice(),
        }
    }
}

#[cfg(test)]
impl Drop for UdpRecvScratch {
    fn drop(&mut self) {
        UDP_RECV_SCRATCH_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
static UDP_RECV_SCRATCH_ACTIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static UDP_RECV_SCRATCH_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static UDP_RECV_SCRATCH_PEAK: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static UDP_RECV_WOULD_BLOCKS: AtomicUsize = AtomicUsize::new(0);

pub(super) async fn try_new_service(
    _: TransparentProxyServiceContext,
    udp_policy_scope: UdpPolicyScope,
) -> Result<impl Service<UdpFlow, Output = (), Error = Infallible>, BoxError> {
    Ok(service_fn(move |flow| service(flow, udp_policy_scope)))
}

/// UDP flow handler used by the transparent proxy engine.
///
/// UDP is connectionless and multi-peer by design: an app may send
/// datagrams to several remotes on the same flow (DNS-over-multiple-
/// resolvers, NTP burst, mDNS, peer-to-peer game protocols). The
/// engine threads the per-datagram peer through `Datagram::peer`
/// specifically so a service can route each outbound datagram with
/// `send_to(peer)` on a single *unconnected* socket and tag each
/// reply with the actual source via `recv_from`.
///
/// This example lazily binds one egress socket per address family
/// the flow actually uses (IPv4 / IPv6). On macOS, AF_INET6 sockets
/// default to `IPV6_V6ONLY=1`, so a single dual-stack listener
/// isn't portable; the two-socket variant is straightforward and
/// keeps multi-peer mixed-family flows working. Both families are
/// idle until first use, so the common single-family flow only
/// pays for the one socket.
///
/// Production handlers may pool sockets across flows, share a
/// single listener for an entire family of flows, or wrap a
/// higher-level rama-udp transport.
///
/// `ConnectorTarget` in the flow's extensions is informational — the
/// first peer the app addressed when the flow was opened — not a
/// binding constraint; we log it for telemetry only.
async fn service(mut ingress: UdpFlow, udp_policy_scope: UdpPolicyScope) -> Result<(), Infallible> {
    #[cfg(not(any(test, feature = "e2e")))]
    let _ = udp_policy_scope;
    #[cfg(any(test, feature = "e2e"))]
    let flow_meta = ingress.extensions().get_arc::<TransparentProxyFlowMeta>();
    let initial_target_hwp = ingress
        .extensions()
        .get_ref()
        .cloned()
        .map(|ConnectorTarget(addr)| addr);

    // The NE kernel surfaces UDP remote endpoints as already-resolved
    // IPs (transparent proxy intercepts post-connect / per-datagram
    // sendto traffic), so the cast is the common case. If a non-IP
    // host ever sneaks through, fallback is simply unavailable for
    // that flow.
    let initial_target: Option<SocketAddr> = initial_target_hwp.as_ref().and_then(|hwp| {
        hwp.host
            .try_as_ip()
            .ok()
            .map(|ip| SocketAddr::new(ip, hwp.port))
    });

    tracing::info!(
        initial_target = ?initial_target_hwp,
        "tproxy udp forwarding started"
    );

    #[cfg(any(test, feature = "e2e"))]
    let mut pressure_probe_pending = true;

    // Egress state per address family. Receive scratch is shared by all flows
    // polled on the same Tokio worker rather than retained by every socket.
    let mut egress_v4: Option<UdpSocket> = None;
    let mut egress_v6: Option<UdpSocket> = None;
    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;

    loop {
        // The select! arms below participate only when the
        // matching-family socket is already bound (`if` guards).
        tokio::select! {
            maybe_datagram = ingress.recv() => {
                let Some(datagram) = maybe_datagram else { break };
                let Some(peer) = datagram.peer.or(initial_target) else {
                    // No per-datagram peer (rare kernel-attribution gap)
                    // and no initial target either — nowhere to send.
                    continue;
                };
                #[cfg(any(test, feature = "e2e"))]
                let (datagram, peer) = {
                    let mut datagram = datagram;
                    let mut peer = peer;
                    if pressure_probe_pending {
                        pressure_probe_pending = false;
                        if should_hold_e2e_pressure_flow(
                            udp_policy_scope,
                            std::time::Instant::now(),
                            flow_meta.as_deref(),
                            peer,
                            &datagram.payload,
                        ) {
                            let Some(next) = hold_and_sink_e2e_pressure_flow(
                                &mut ingress,
                                datagram,
                                udp_policy_scope,
                                flow_meta.as_deref(),
                                initial_target,
                            ).await else { break };
                            // The first non-probe datagram returns to ordinary
                            // forwarding with its original payload and peer.
                            datagram = next;
                            let Some(next_peer) = datagram.peer.or(initial_target) else {
                                continue;
                            };
                            peer = next_peer;
                        }
                    }
                    (datagram, peer)
                };
                let socket = match peer {
                    SocketAddr::V4(_) => match ensure_bound(&mut egress_v4, "0.0.0.0:0").await {
                        Some(s) => s,
                        None => break,
                    },
                    SocketAddr::V6(_) => match ensure_bound(&mut egress_v6, "[::]:0").await {
                        Some(s) => s,
                        None => break,
                    },
                };
                up_packets += 1;
                up_bytes += datagram.payload.len() as u64;
                if let Err(err) = socket.send_to(&datagram.payload, peer).await {
                    tracing::warn!(%err, %peer, "tproxy udp egress send_to failed");
                    break;
                }
            }
            res = recv_from_slot(egress_v4.as_ref()), if egress_v4.is_some() => {
                match res {
                    Ok((n, peer, payload)) => {
                        down_packets += 1;
                        down_bytes += n as u64;
                        ingress.send(Datagram::new(payload, peer));
                    }
                    Err(err) => {
                        tracing::warn!(%err, family = "v4", "tproxy udp egress recv_from failed; tearing socket down");
                        // Drop the slot so the next loop iteration stops
                        // polling it. Otherwise a broken socket can re-error
                        // every iteration and amplify the log without making
                        // progress.
                        egress_v4 = None;
                    }
                }
            }
            res = recv_from_slot(egress_v6.as_ref()), if egress_v6.is_some() => {
                match res {
                    Ok((n, peer, payload)) => {
                        down_packets += 1;
                        down_bytes += n as u64;
                        ingress.send(Datagram::new(payload, peer));
                    }
                    Err(err) => {
                        tracing::warn!(%err, family = "v6", "tproxy udp egress recv_from failed; tearing socket down");
                        egress_v6 = None;
                    }
                }
            }
        }
    }

    tracing::info!(
        up_packets,
        up_bytes,
        down_packets,
        down_bytes,
        "tproxy udp forwarding done"
    );

    Ok(())
}

#[cfg(any(test, feature = "e2e"))]
#[derive(Default)]
struct E2ePressureRetention {
    payloads: Vec<Bytes>,
    bytes: usize,
}

#[cfg(any(test, feature = "e2e"))]
impl E2ePressureRetention {
    fn retain(&mut self, payload: Bytes) {
        if self.payloads.len() < E2E_PRESSURE_MAX_RETAINED_ITEMS
            && payload.len() <= DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES - self.bytes
        {
            self.bytes += payload.len();
            self.payloads.push(payload);
        }
    }
}

/// Exercise physical ingress-byte retention without withholding read demand.
///
/// Sleeping immediately after the first `recv` prevents subsequent Apple
/// reads: another `recv` is the only ordinary demand edge. Retaining charged
/// payload roots while continuing to receive can instead fill the real flow
/// byte budget without requiring an oversized Swift callback batch. The
/// independent timer must release roots even while pressure parks `recv`.
#[cfg(any(test, feature = "e2e"))]
async fn hold_and_sink_e2e_pressure_flow(
    ingress: &mut UdpFlow,
    first: Datagram,
    scope: UdpPolicyScope,
    meta: Option<&TransparentProxyFlowMeta>,
    initial_target: Option<SocketAddr>,
) -> Option<Datagram> {
    let mut retained = E2ePressureRetention::default();
    retained.retain(first.payload);
    let mut retained = Some(retained);
    let hold = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(hold);
    loop {
        tokio::select! {
            biased;
            () = &mut hold, if retained.is_some() => {
                retained = None;
            }
            next = ingress.recv() => {
                let datagram = next?;
                let Some(peer) = datagram.peer.or(initial_target) else {
                    return Some(datagram);
                };
                if !should_hold_e2e_pressure_flow(
                    scope, std::time::Instant::now(), meta, peer, &datagram.payload,
                ) {
                    return Some(datagram);
                }
                if let Some(retained) = &mut retained {
                    retained.retain(datagram.payload);
                }
                // Only the scoped marker protocol is consumed here. It is
                // deliberately not NTP, so do not send its remaining packets
                // to a public NTP server after the retention window expires.
            }
        }
    }
}

#[cfg(any(test, feature = "e2e"))]
fn should_hold_e2e_pressure_flow(
    scope: UdpPolicyScope,
    now: std::time::Instant,
    meta: Option<&TransparentProxyFlowMeta>,
    peer: SocketAddr,
    payload: &[u8],
) -> bool {
    if !scope.is_e2e_active_at(now) {
        return false;
    }
    let Some(meta) = meta else { return false };
    if meta.source_app_bundle_identifier.as_deref() != Some("com.apple.python3") {
        return false;
    }
    let Some(remote) = meta.remote_endpoint.as_ref() else {
        return false;
    };
    if remote.port != peer.port() || remote.host.try_as_ip().ok() != Some(peer.ip()) {
        return false;
    }
    let Some(declared) = payload.strip_prefix(E2E_PRESSURE_MARKER) else {
        return false;
    };
    let Some(terminator) = declared.iter().position(|byte| *byte == 0) else {
        return false;
    };
    std::str::from_utf8(&declared[..terminator])
        .ok()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        == Some(peer)
}

/// Lazily bind a per-family egress socket on first use. Returns
/// `None` and logs on bind failure (the caller treats this as a
/// flow-terminal condition).
async fn ensure_bound<'s>(
    slot: &'s mut Option<UdpSocket>,
    bind_addr: &str,
) -> Option<&'s UdpSocket> {
    if slot.is_none() {
        match bind_udp_with_address(bind_addr).await {
            Ok(socket) => *slot = Some(socket),
            Err(err) => {
                tracing::error!(%err, bind_addr, "tproxy udp failed to bind egress socket");
                return None;
            }
        }
    }
    slot.as_ref()
}

/// Wrapper used inside `tokio::select!` arms. `None` shorts to `pending()` so
/// the arm's `if` guard is the only gate that matters.
///
/// Readiness can be a false positive, so `WouldBlock` returns to `readable()`
/// instead of spinning. All other errors propagate so the caller tears the
/// socket down and cannot repeatedly poll/log a permanently broken socket.
async fn recv_from_slot(
    slot: Option<&UdpSocket>,
) -> std::io::Result<(usize, SocketAddr, rama::bytes::Bytes)> {
    let Some(socket) = slot else {
        return std::future::pending().await;
    };

    loop {
        socket.readable().await?;

        let result = UDP_RECV_SCRATCH.with(|slot| {
            let mut slot = slot.borrow_mut();
            let scratch = slot.get_or_insert_with(UdpRecvScratch::new);
            socket.try_recv_from(&mut scratch.bytes).map(|(n, peer)| {
                (
                    n,
                    peer,
                    rama::bytes::Bytes::copy_from_slice(&scratch.bytes[..n]),
                )
            })
        });

        match result {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                #[cfg(test)]
                UDP_RECV_WOULD_BLOCKS.fetch_add(1, Ordering::Relaxed);
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        net::apple::networkextension::tproxy::{
            FlowAction, SessionFlowAction, TransparentProxyConfig, TransparentProxyEngineBuilder,
            TransparentProxyFlowProtocol, TransparentProxyHandler,
        },
        rt::Executor,
    };
    use std::sync::{Arc, mpsc};

    const TEST_WORKERS: usize = 2;
    const CONCURRENT_FLOWS: usize = 64;

    fn datagram_payload(len: usize, salt: usize) -> Vec<u8> {
        (0..len)
            .map(|index| ((index.wrapping_mul(31).wrapping_add(salt)) % 251) as u8)
            .collect()
    }

    fn is_message_too_long(err: &io::Error) -> bool {
        // EMSGSIZE is 40 on Apple/BSD, 90 on Linux, and 10040 in Winsock.
        matches!(err.raw_os_error(), Some(40 | 90 | 10_040))
    }

    async fn check_datagram_size(len: usize, ipv6: bool) -> bool {
        let bind_addr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
        let receiver = match UdpSocket::bind(bind_addr).await {
            Ok(receiver) => receiver,
            Err(err) if ipv6 => {
                eprintln!("skipping unavailable IPv6 loopback: {err}");
                return false;
            }
            Err(err) => panic!("IPv4 loopback must be available: {err}"),
        };
        let sender = UdpSocket::bind(bind_addr).await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let expected = datagram_payload(len, 17);

        match sender.send_to(&expected, receiver_addr).await {
            Ok(n) => assert_eq!(n, len),
            Err(err) if len >= 65_507 && is_message_too_long(&err) => {
                // macOS's configured UDP maximum and the loopback MTU can be
                // lower than the protocol's payload ceiling. Still attempt
                // both upper boundaries and skip only when the kernel rejects
                // the send; the other boundary sizes remain mandatory.
                eprintln!("skipping unsupported {len}-byte UDP datagram: {err}");
                return false;
            }
            Err(err) => panic!("failed to send {len}-byte UDP datagram: {err}"),
        }

        let received = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), recv_from_slot(Some(&receiver)))
                .await
                .expect("UDP receive timed out")
                .expect("UDP receive failed")
        })
        .await
        .expect("UDP receive task panicked");

        assert_eq!(received.0, len);
        assert_eq!(received.1, sender_addr);
        assert_eq!(received.2.as_ref(), expected);
        true
    }

    async fn check_readiness_false_positive() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        sender.send_to(b"stale", receiver_addr).await.unwrap();
        receiver.readable().await.unwrap();
        let mut drained = [0; 5];
        assert_eq!(receiver.try_recv_from(&mut drained).unwrap().0, 5);
        assert_eq!(&drained, b"stale");

        // A successful `try_recv_from` deliberately leaves Tokio's readiness
        // bit set because another datagram may already be queued. With the
        // queue now empty, the receive helper must observe `WouldBlock`, clear
        // that stale readiness, and await the next edge without spinning.
        let would_blocks_before = UDP_RECV_WOULD_BLOCKS.load(Ordering::Relaxed);
        let receive = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), recv_from_slot(Some(&receiver)))
                .await
                .expect("receive did not recover from stale readiness")
                .expect("receive failed after stale readiness")
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while UDP_RECV_WOULD_BLOCKS.load(Ordering::Relaxed) == would_blocks_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test failed to induce a readiness false positive");

        sender.send_to(b"fresh", receiver_addr).await.unwrap();
        let (n, _, payload) = receive.await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(payload.as_ref(), b"fresh");
    }

    async fn check_concurrent_flows() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut receives = Vec::with_capacity(CONCURRENT_FLOWS);
        let mut destinations = Vec::with_capacity(CONCURRENT_FLOWS);

        for flow in 0..CONCURRENT_FLOWS {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            destinations.push((
                receiver.local_addr().unwrap(),
                datagram_payload(1_200, flow),
            ));
            receives.push(tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(3), recv_from_slot(Some(&receiver)))
                    .await
                    .expect("concurrent UDP receive timed out")
                    .expect("concurrent UDP receive failed")
            }));
        }

        tokio::task::yield_now().await;
        for (destination, payload) in &destinations {
            assert_eq!(
                sender.send_to(payload, destination).await.unwrap(),
                payload.len()
            );
        }

        for (receive, (_, expected)) in receives.into_iter().zip(destinations) {
            let (n, peer, payload) = receive.await.unwrap();
            assert_eq!(n, expected.len());
            assert_eq!(peer, sender_addr);
            assert_eq!(payload.as_ref(), expected);
        }
    }

    #[test]
    fn worker_scratch_preserves_udp_datagrams_and_is_not_per_flow() {
        assert_eq!(
            UDP_RECV_SCRATCH_ACTIVE.load(Ordering::Relaxed),
            0,
            "no other test may retain this test-only receive scratch"
        );
        let allocations_before = UDP_RECV_SCRATCH_ALLOCATIONS.load(Ordering::Relaxed);
        UDP_RECV_SCRATCH_PEAK.store(0, Ordering::Relaxed);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(TEST_WORKERS)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for len in [0, 1, 1_200, 1_350, 1_472, 8_192] {
                assert!(check_datagram_size(len, false).await);
            }
            let _platform_supports_max_ipv4 = check_datagram_size(65_507, false).await;
            let _platform_supports_max_ipv6 = check_datagram_size(65_527, true).await;
            check_readiness_false_positive().await;
            check_concurrent_flows().await;
        });
        drop(runtime);

        let allocations = UDP_RECV_SCRATCH_ALLOCATIONS.load(Ordering::Relaxed) - allocations_before;
        let peak = UDP_RECV_SCRATCH_PEAK.load(Ordering::Relaxed);
        assert!(allocations > 0);
        assert!(
            allocations <= TEST_WORKERS,
            "{allocations} scratch allocations exceeded {TEST_WORKERS} runtime workers"
        );
        assert!(
            peak <= TEST_WORKERS,
            "peak scratch count {peak} exceeded {TEST_WORKERS} runtime workers"
        );
        assert!(allocations < CONCURRENT_FLOWS);
        assert_eq!(UDP_RECV_SCRATCH_ACTIVE.load(Ordering::Relaxed), 0);
    }

    fn meta(endpoint: &str, bundle_identifier: &str) -> TransparentProxyFlowMeta {
        let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
        meta.remote_endpoint = Some(endpoint.parse().expect("valid endpoint"));
        meta.source_app_bundle_identifier = Some(
            bundle_identifier
                .parse()
                .expect("non-empty bundle identifier"),
        );
        meta
    }

    fn pressure_payload(endpoint: &str) -> Vec<u8> {
        let mut payload = E2E_PRESSURE_MARKER.to_vec();
        payload.extend_from_slice(endpoint.as_bytes());
        payload.push(0);
        payload.resize(4096, 0);
        payload
    }

    #[test]
    fn pressure_retention_bounds_owned_bytes_and_items_and_releases_every_root() {
        struct OwnedPayload {
            bytes: [u8; 64],
            drops: Arc<AtomicUsize>,
        }
        impl AsRef<[u8]> for OwnedPayload {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for OwnedPayload {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut retained = E2ePressureRetention::default();
        for _ in 0..4_097 {
            retained.retain(Bytes::from_owner(OwnedPayload {
                bytes: [0; 64],
                drops: drops.clone(),
            }));
        }
        assert_eq!(retained.payloads.len(), 4_096);
        assert_eq!(retained.bytes, kib(256));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        drop(retained);
        assert_eq!(drops.load(Ordering::Relaxed), 4_097);

        let mut retained = E2ePressureRetention::default();
        retained.retain(Bytes::from(vec![
            0;
            DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES + 1
        ]));
        assert!(retained.payloads.is_empty());
        for _ in 0..4_097 {
            retained.retain(Bytes::from_static(b"x"));
        }
        assert_eq!(retained.payloads.len(), 4_096);
        assert_eq!(retained.bytes, 4_096);
    }

    #[derive(Clone)]
    struct PressureTestHandler {
        scope: UdpPolicyScope,
        result: mpsc::Sender<Option<Datagram>>,
        released: mpsc::Sender<()>,
    }

    struct ObservedChargedRoot {
        payload: Option<Bytes>,
        released: mpsc::Sender<()>,
    }

    impl AsRef<[u8]> for ObservedChargedRoot {
        fn as_ref(&self) -> &[u8] {
            self.payload.as_ref().expect("live payload root")
        }
    }

    impl Drop for ObservedChargedRoot {
        fn drop(&mut self) {
            drop(self.payload.take());
            _ = self.released.send(());
        }
    }

    impl TransparentProxyHandler for PressureTestHandler {
        fn transparent_proxy_config(&self) -> TransparentProxyConfig {
            TransparentProxyConfig::default()
        }

        async fn match_udp_flow(
            &self,
            _exec: Executor,
            meta: TransparentProxyFlowMeta,
        ) -> FlowAction<impl Service<UdpFlow, Output = (), Error = Infallible>> {
            let result = self.result.clone();
            let released = self.released.clone();
            let scope = self.scope;
            let service_meta = meta.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: UdpFlow| {
                    let result = result.clone();
                    let released = released.clone();
                    let meta = service_meta.clone();
                    async move {
                        let mut first = flow.recv().await.expect("initial pressure marker");
                        first.payload = Bytes::from_owner(ObservedChargedRoot {
                            payload: Some(first.payload),
                            released,
                        });
                        let initial_target = first.peer;
                        assert!(should_hold_e2e_pressure_flow(
                            scope,
                            std::time::Instant::now(),
                            Some(&meta),
                            initial_target.expect("pressure peer"),
                            &first.payload,
                        ));
                        let next = hold_and_sink_e2e_pressure_flow(
                            &mut flow,
                            first,
                            scope,
                            Some(&meta),
                            initial_target,
                        )
                        .await;
                        _ = result.send(next);
                        Ok(())
                    }
                }),
            }
        }
    }

    #[test]
    fn pressure_hold_keeps_default_engine_reads_active_and_releases_on_pending_recv() {
        let (result_tx, result_rx) = mpsc::channel();
        let (released_tx, released_rx) = mpsc::channel();
        let handler = PressureTestHandler {
            scope: UdpPolicyScope::new(true, std::time::Instant::now()),
            result: result_tx,
            released: released_tx,
        };
        let engine = TransparentProxyEngineBuilder::new(move |_| {
            std::future::ready(Ok::<_, Infallible>(handler.clone()))
        })
        .build()
        .expect("default engine for an in-process pressure fixture");
        let (demand_tx, demand_rx) = mpsc::channel();
        let (close_tx, close_rx) = mpsc::channel();
        let peer = "162.159.200.1:123".parse().unwrap();
        let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
            meta("162.159.200.1:123", "com.apple.python3"),
            |_| panic!("the diagnostic marker must not produce egress"),
            move |_| _ = demand_tx.send(()),
            move || _ = close_tx.send(()),
        ) else {
            panic!("expected an intercepted in-process flow");
        };
        session.activate();
        let started = std::time::Instant::now();
        let payload = pressure_payload("162.159.200.1:123");
        // Exactly one packet per read demand keeps the 32-slot channel empty
        // between receives. Retained charged roots, not channel count or a
        // synthetic counter, must account for the following pressure pause.
        for _ in 0..65 {
            demand_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("the retention window must continue pulling ingress");
            session.on_client_datagram(&payload, Some(peer));
        }
        assert_eq!(
            demand_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "the 65th 4-KiB packet must pause the physically full byte budget"
        );
        released_rx
            .try_recv()
            .expect_err("the charged marker root must remain held while reads are paused");
        demand_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the independent hold timer must refund roots and resume ingress");
        assert!(started.elapsed() >= Duration::from_secs(2));
        released_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the timer must destroy the charged root before the recovery canary");
        // The probe marker remains a diagnostic sink after the hold, while a
        // following unmarked packet must still reach ordinary forwarding.
        session.on_client_datagram(&payload, Some(peer));
        let canary = vec![0x23; 4096];
        session.on_client_datagram(&canary, Some(peer));
        let returned = result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ordinary canary must resume after payload release")
            .expect("the unmarked canary must return to ordinary forwarding");
        assert_eq!(returned.payload.as_ref(), canary);
        assert_eq!(returned.peer, Some(peer));
        drop(returned);
        close_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the fixture service must finish its close callback");
        session.on_client_close();
        engine.stop(0);
        close_rx
            .try_recv()
            .expect_err("the fixture must not duplicate its close callback");
    }

    #[test]
    fn pressure_hold_releases_charged_roots_when_pending_service_is_cancelled() {
        let (result_tx, result_rx) = mpsc::channel();
        let (released_tx, released_rx) = mpsc::channel();
        let handler = PressureTestHandler {
            scope: UdpPolicyScope::new(true, std::time::Instant::now()),
            result: result_tx,
            released: released_tx,
        };
        let engine = TransparentProxyEngineBuilder::new(move |_| {
            std::future::ready(Ok::<_, Infallible>(handler.clone()))
        })
        .build()
        .expect("default engine for a cancelled in-process pressure fixture");
        let (demand_tx, demand_rx) = mpsc::channel();
        let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
            meta("162.159.200.1:123", "com.apple.python3"),
            |_| panic!("the diagnostic marker must not produce egress"),
            move |_| _ = demand_tx.send(()),
            || {},
        ) else {
            panic!("expected an intercepted in-process flow");
        };
        session.activate();
        demand_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        session.on_client_datagram(
            &pressure_payload("162.159.200.1:123"),
            Some("162.159.200.1:123".parse().unwrap()),
        );
        demand_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the helper must retain the marker and await more ingress");
        released_rx
            .try_recv()
            .expect_err("the marker root must remain held before cancellation");
        session.on_client_close();
        released_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cancellation must destroy the held charged root without awaiting the timer");
        engine.stop(0);
        // Closing ingress can produce EOF before cooperative cancellation wins
        // the service select. Neither terminal path may return a datagram.
        assert!(
            !matches!(result_rx.try_recv(), Ok(Some(_))),
            "cancellation must not forward the consumed diagnostic marker"
        );
    }

    #[test]
    fn pressure_hold_requires_active_python_flow_and_exact_peer_marker() {
        let start = std::time::Instant::now();
        let scope = UdpPolicyScope::new(true, start);
        let peer: SocketAddr = "162.159.200.1:123".parse().unwrap();
        let python = meta("162.159.200.1:123", "com.apple.python3");
        let payload = pressure_payload("162.159.200.1:123");
        assert!(should_hold_e2e_pressure_flow(
            scope,
            start,
            Some(&python),
            peer,
            &payload,
        ));

        let background = meta("162.159.200.1:123", "com.example.background");
        assert!(!should_hold_e2e_pressure_flow(
            scope,
            start,
            Some(&background),
            peer,
            &payload,
        ));
        assert!(!should_hold_e2e_pressure_flow(
            scope,
            start,
            Some(&python),
            "162.159.200.2:123".parse().unwrap(),
            &payload,
        ));
        assert!(!should_hold_e2e_pressure_flow(
            scope,
            start,
            Some(&python),
            peer,
            &pressure_payload("162.159.200.2:123"),
        ));
        assert!(!should_hold_e2e_pressure_flow(
            scope,
            start,
            Some(&python),
            peer,
            &[0x23; 48],
        ));
    }

    #[test]
    fn pressure_hold_expires_with_the_temporary_e2e_scope() {
        let start = std::time::Instant::now();
        let scope = UdpPolicyScope::new(true, start);
        let peer: SocketAddr = "162.159.200.1:123".parse().unwrap();
        let python = meta("162.159.200.1:123", "com.apple.python3");
        assert!(!should_hold_e2e_pressure_flow(
            scope,
            start + super::super::UDP_E2E_SAFETY_LIFETIME,
            Some(&python),
            peer,
            &pressure_payload("162.159.200.1:123"),
        ));
        assert!(!should_hold_e2e_pressure_flow(
            UdpPolicyScope::Normal,
            start,
            Some(&python),
            peer,
            &pressure_payload("162.159.200.1:123"),
        ));
    }
}
