use std::convert::Infallible;

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    net::{
        apple::networkextension::{Datagram, UdpFlow, tproxy::TransparentProxyServiceContext},
        proxy::ProxyTarget,
    },
    service::service_fn,
    telemetry::tracing,
    udp::bind_udp_with_address,
};

pub(super) async fn try_new_service(
    _: TransparentProxyServiceContext,
) -> Result<impl Service<UdpFlow, Output = (), Error = Infallible>, BoxError> {
    Ok(service_fn(service))
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
/// This example uses one unconnected socket per flow — simple,
/// preserves multi-peer fidelity, and works equally well for the
/// degenerate single-peer case (HTTP/3 / QUIC). Production handlers
/// may pool sockets across flows, share a single listener for an
/// entire family of flows, or wrap a higher-level rama-udp transport.
///
/// `ProxyTarget` in the flow's extensions is informational — the
/// first peer the app addressed when the flow was opened — not a
/// binding constraint; we log it for telemetry only.
async fn service(mut ingress: UdpFlow) -> Result<(), Infallible> {
    let initial_target_hwp = ingress
        .extensions()
        .get_ref()
        .cloned()
        .map(|ProxyTarget(addr)| addr);
    // The NE kernel surfaces UDP remote endpoints as already-resolved
    // IPs (transparent proxy intercepts post-connect / per-datagram
    // sendto traffic), so the cast is the common case. If a non-IP
    // host ever sneaks through, fallback is simply unavailable for
    // that flow.
    let initial_target: Option<std::net::SocketAddr> = initial_target_hwp
        .as_ref()
        .and_then(|hwp| match hwp.host {
            rama::net::address::Host::Address(ip) => {
                Some(std::net::SocketAddr::new(ip, hwp.port))
            }
            rama::net::address::Host::Name(_) => None,
        });

    let egress = match bind_udp_with_address("0.0.0.0:0").await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(%err, "tproxy udp failed to bind egress socket");
            while ingress.recv().await.is_some() {}
            return Ok(());
        }
    };

    tracing::info!(
        initial_target = ?initial_target_hwp,
        "tproxy udp forwarding started"
    );

    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        tokio::select! {
            maybe_datagram = ingress.recv() => {
                let Some(datagram) = maybe_datagram else { break };
                let Some(peer) = datagram.peer.or(initial_target) else {
                    // No per-datagram peer (rare kernel-attribution gap)
                    // and no initial target either — nowhere to send.
                    continue;
                };
                up_packets += 1;
                up_bytes += datagram.payload.len() as u64;
                if let Err(err) = egress.send_to(&datagram.payload, peer).await {
                    tracing::warn!(%err, %peer, "tproxy udp egress send_to failed");
                    break;
                }
            }
            recv = egress.recv_from(&mut buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(%err, "tproxy udp egress recv_from failed");
                        break;
                    }
                };
                down_packets += 1;
                down_bytes += n as u64;
                let payload = rama::bytes::Bytes::copy_from_slice(&buf[..n]);
                ingress.send(Datagram::new(payload, peer));
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
