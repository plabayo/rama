use std::convert::Infallible;
use std::net::SocketAddr;

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
    udp::{UdpSocket, bind_udp_with_address},
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
    let initial_target: Option<SocketAddr> = initial_target_hwp.as_ref().and_then(|hwp| {
        match hwp.host {
            rama::net::address::Host::Address(ip) => Some(SocketAddr::new(ip, hwp.port)),
            rama::net::address::Host::Name(_) => None,
        }
    });

    tracing::info!(
        initial_target = ?initial_target_hwp,
        "tproxy udp forwarding started"
    );

    let mut egress_v4: Option<UdpSocket> = None;
    let mut egress_v6: Option<UdpSocket> = None;
    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    // Independent buffers per family so `tokio::select!` can poll
    // both `recv_from`s concurrently without a double-mutable-borrow
    // conflict on a shared scratch.
    let mut buf_v4 = vec![0u8; 64 * 1024];
    let mut buf_v6 = vec![0u8; 64 * 1024];

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
            res = recv_from_optional(egress_v4.as_ref(), &mut buf_v4), if egress_v4.is_some() => {
                match res {
                    Ok((n, peer)) => {
                        let payload = rama::bytes::Bytes::copy_from_slice(&buf_v4[..n]);
                        down_packets += 1;
                        down_bytes += n as u64;
                        ingress.send(Datagram::new(payload, peer));
                    }
                    Err(err) => {
                        tracing::warn!(%err, family = "v4", "tproxy udp egress recv_from failed; tearing socket down");
                        // Drop the socket so the next loop iteration
                        // stops polling it — otherwise the broken
                        // socket re-errors on every iteration and
                        // spams the log without making progress.
                        egress_v4 = None;
                    }
                }
            }
            res = recv_from_optional(egress_v6.as_ref(), &mut buf_v6), if egress_v6.is_some() => {
                match res {
                    Ok((n, peer)) => {
                        let payload = rama::bytes::Bytes::copy_from_slice(&buf_v6[..n]);
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

/// Lazily bind a per-family egress socket on first use. Returns
/// `None` and logs on bind failure (the caller treats this as a
/// flow-terminal condition).
async fn ensure_bound<'s>(
    slot: &'s mut Option<UdpSocket>,
    bind_addr: &str,
) -> Option<&'s UdpSocket> {
    if slot.is_none() {
        match bind_udp_with_address(bind_addr).await {
            Ok(s) => *slot = Some(s),
            Err(err) => {
                tracing::error!(%err, bind_addr, "tproxy udp failed to bind egress socket");
                return None;
            }
        }
    }
    slot.as_ref()
}

/// `recv_from` wrapper that lets the `select!` branch guard cleanly
/// short-circuit when the socket is `None`. The branch's `if` guard
/// ensures this is only polled with `Some`. Errors propagate to the
/// caller so it can tear down the broken socket — otherwise a hard
/// error (interface down, etc.) would spam the log on every
/// `select!` cycle.
async fn recv_from_optional(
    socket: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}
