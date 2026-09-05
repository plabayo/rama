use std::convert::Infallible;
use std::{net::SocketAddr, time::Duration};

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    net::{
        apple::networkextension::{
            Datagram, UdpFlow,
            tproxy::{TransparentProxyFlowMeta, TransparentProxyServiceContext},
        },
        client::ConnectorTarget,
    },
    service::service_fn,
    telemetry::tracing,
    udp::{UdpSocket, bind_udp_with_address},
    utils::octets::kib,
};

use super::UdpPolicyScope;

const E2E_PRESSURE_MARKER: &[u8] = b"rama-udp-e2e-pressure-v1 ";

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

    // The signed E2E's first pressure datagram carries a versioned marker and
    // its exact peer. Only an active, allowlisted Python flow whose metadata,
    // datagram peer, and marker all agree may pause. Consuming that first
    // datagram before the hold still leaves the production-sized channel to be
    // filled by the remaining 511 datagrams. Ordinary NTP/HTTP3/background
    // traffic and an expired E2E scope never take this path.
    let mut pressure_probe_pending = true;

    // Egress state per address family — socket + recv buffer
    // allocated together, lazily, on first use of that family. A
    // single-family flow (the overwhelming common case) thus only
    // pays for one 64 KiB buffer, not two. The recv buffers being
    // bound to the same `Option` as the socket means a torn-down
    // socket also frees its buffer.
    let mut egress_v4: Option<(UdpSocket, Vec<u8>)> = None;
    let mut egress_v6: Option<(UdpSocket, Vec<u8>)> = None;
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
                if pressure_probe_pending {
                    pressure_probe_pending = false;
                    if should_hold_e2e_pressure_flow(
                        udp_policy_scope,
                        std::time::Instant::now(),
                        flow_meta.as_deref(),
                        peer,
                        &datagram.payload,
                    ) {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
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
            res = recv_from_mut_pair(egress_v4.as_mut()), if egress_v4.is_some() => {
                match res {
                    Ok((n, peer, payload)) => {
                        down_packets += 1;
                        down_bytes += n as u64;
                        ingress.send(Datagram::new(payload, peer));
                    }
                    Err(err) => {
                        tracing::warn!(%err, family = "v4", "tproxy udp egress recv_from failed; tearing socket down");
                        // Drop the slot so the next loop iteration
                        // stops polling it — otherwise the broken
                        // socket re-errors on every iteration and
                        // spams the log. Dropping also releases the
                        // 64 KiB recv buffer.
                        egress_v4 = None;
                    }
                }
            }
            res = recv_from_mut_pair(egress_v6.as_mut()), if egress_v6.is_some() => {
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
/// flow-terminal condition). Allocates the per-family receive
/// buffer alongside the socket so an idle family pays nothing.
async fn ensure_bound<'s>(
    slot: &'s mut Option<(UdpSocket, Vec<u8>)>,
    bind_addr: &str,
) -> Option<&'s UdpSocket> {
    if slot.is_none() {
        match bind_udp_with_address(bind_addr).await {
            Ok(s) => *slot = Some((s, vec![0u8; kib(64)])),
            Err(err) => {
                tracing::error!(%err, bind_addr, "tproxy udp failed to bind egress socket");
                return None;
            }
        }
    }
    slot.as_ref().map(|(s, _buf)| s)
}

/// Wrapper used inside `tokio::select!` arms — receives one
/// datagram on the slot's socket into the slot's buffer, returning
/// the byte count, peer, and a freshly-cloned `Bytes` payload.
/// `None` shorts to `pending()` so the arm `if` guard is the only
/// gate that matters.
///
/// Errors propagate so the caller can tear down the slot — without
/// that, a hard error (interface down, etc.) would re-error on
/// every `select!` cycle and spam the log without making progress.
async fn recv_from_mut_pair(
    slot: Option<&mut (UdpSocket, Vec<u8>)>,
) -> std::io::Result<(usize, SocketAddr, rama::bytes::Bytes)> {
    match slot {
        Some((socket, buf)) => {
            let (n, peer) = socket.recv_from(buf).await?;
            Ok((n, peer, rama::bytes::Bytes::copy_from_slice(&buf[..n])))
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::net::apple::networkextension::tproxy::TransparentProxyFlowProtocol;

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
