//! Rust-owned UDP egress for a transparent-proxy session.
//!
//! NEAppProxyUDPFlow is unconnected from the kernel's perspective and
//! the per-datagram source/destination endpoints come back via
//! `flow.readDatagrams` / `flow.writeDatagrams`. The matching transport
//! layer should be a single unconnected UDP socket on the egress side
//! — one socket per intercepted flow, `send_to(addr)` per datagram,
//! `recv_from()` returning the source per datagram. Network framework
//! has no such surface (`NWConnection` is connection-pinned and
//! `NWConnectionGroup` only does multicast), so a faithful UDP proxy
//! has to drop back to BSD sockets. Apple's own TN3151 explicitly
//! recommends this for "asymmetric designs" — multi-peer client UDP
//! qualifies.
//!
//! By keeping the socket on the Rust side we also benefit from
//! tokio's well-tested `UdpSocket` and avoid maintaining a per-peer
//! NWConnection pool + LRU + idle-reap on the Swift side.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use rama_core::bytes::Bytes;
use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::Datagram;
use crate::tproxy::types::NwUdpConnectOptions;

/// Maximum payload size for a UDP datagram read. RFC 768 caps the
/// payload at 65,507 bytes (65535 - 8 byte UDP header - 20 byte IPv4
/// header), but in practice IPv6 jumbograms can carry more. 65,535
/// is the upper bound the receive buffer ever needs.
const UDP_RECV_BUFFER: usize = 65_535;

/// The bound egress side of a UDP session.
///
/// Holds the BSD UDP socket plus the two tokio tasks driving it
/// (`recv_from` reading from the wire into the bridge's egress
/// receiver, and a task that pulls service-side sends out of the
/// bridge and dispatches them to `send_to`). The handle drops the
/// socket when the session is dropped, which closes the FD and the
/// two tasks return.
pub(super) struct UdpEgress {
    /// Bound local address (read-only after construction). Useful
    /// for diagnostics.
    pub local_addr: SocketAddr,
    /// Sink the bridge writes to. Closing the session drops this
    /// sender, which terminates the send pump.
    pub outbound_tx: mpsc::Sender<Datagram>,
    /// Tasks pumping the socket. Stored so the session can join /
    /// abort on drop.
    _send_task: tokio::task::JoinHandle<()>,
    _recv_task: tokio::task::JoinHandle<()>,
}

/// Bind a fresh unconnected UDP socket for a single intercepted UDP
/// flow's egress.
///
/// `inbound_tx` is the bridge's egress→service sender — the recv
/// pump pushes inbound datagrams here, tagged with the source. The
/// returned [`UdpEgress`] exposes `outbound_tx` for the bridge's
/// service→wire side and parks the two pump tasks on the runtime
/// associated with `exec`. The pumps stop cooperatively when either
/// the socket errors / the channel closes, or when the shutdown
/// guard fires.
///
/// The function is synchronous — it uses `std::net::UdpSocket::bind`
/// up front so a bind failure surfaces immediately as `Err(io::Error)`
/// (rather than being deferred to the first async operation). The
/// socket is then re-armed as non-blocking and handed to tokio.
///
/// `_options` (egress NwUdpConnectOptions) are not yet applied to
/// the BSD socket — see the module note on attribution / service
/// class for the trade-off and what we may add via `setsockopt`
/// later. Hooking them up is a non-blocking iteration on top of
/// this initial commit.
pub(super) fn spawn_udp_egress(
    exec: &Executor,
    flow_guard: &ShutdownGuard,
    inbound_tx: mpsc::Sender<Datagram>,
    udp_channel_capacity: usize,
    _options: Option<&NwUdpConnectOptions>,
) -> io::Result<UdpEgress> {
    // Bind to 0.0.0.0:0 with std for synchronous failure surface,
    // then hand to tokio. The OS picks the source port; the kernel's
    // routing table picks the source interface per `send_to`.
    let std_socket =
        std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    std_socket.set_nonblocking(true)?;
    let local_addr = std_socket.local_addr()?;
    let socket = UdpSocket::from_std(std_socket)?;
    let socket = Arc::new(socket);

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Datagram>(udp_channel_capacity);

    // Send pump: drains outbound_rx, dispatches to the wire.
    let send_socket = Arc::clone(&socket);
    let send_guard = flow_guard.clone();
    let send_task = exec.spawn_task(async move {
        loop {
            tokio::select! {
                () = send_guard.cancelled() => break,
                maybe_datagram = outbound_rx.recv() => {
                    let Some(datagram) = maybe_datagram else { break; };
                    let Some(peer) = datagram.peer else {
                        // No peer attribution means the service /
                        // engine did not know where to send. Dropping
                        // matches the wire — a datagram on the wire
                        // always has a destination; without one we
                        // have nothing to do. Logged once so the
                        // breadcrumb is visible.
                        tracing::debug!(
                            target: "rama_apple_ne::tproxy",
                            "udp egress: dropping datagram with no peer attribution"
                        );
                        continue;
                    };
                    if let Err(err) = send_socket.send_to(&datagram.payload, peer).await {
                        // ICMP unreachable, route failure, etc. — UDP
                        // is lossy by definition; log + keep going.
                        // A persistent error condition will surface
                        // upstream via missing replies (RFC 768
                        // semantics: senders never see acks).
                        tracing::trace!(
                            target: "rama_apple_ne::tproxy",
                            peer = %peer,
                            error = %err,
                            "udp egress send_to failed",
                        );
                    }
                }
            }
        }
        tracing::trace!(target: "rama_apple_ne::tproxy", "udp egress send pump exited");
    });

    // Recv pump: tight loop on recv_from, push tagged Datagrams
    // upstream. Closes when the channel receiver disappears (the
    // bridge dropped its egress half) or the guard fires.
    let recv_socket = Arc::clone(&socket);
    let recv_guard = flow_guard.clone();
    let recv_task = exec.spawn_task(async move {
        // Reuse a single recv buffer across iterations — avoids
        // per-datagram allocation. `recv_socket.recv_from` writes
        // into the buffer and returns `(len, addr)`.
        let mut buf = vec![0u8; UDP_RECV_BUFFER];
        loop {
            tokio::select! {
                () = recv_guard.cancelled() => break,
                result = recv_socket.recv_from(&mut buf) => {
                    let (n, peer) = match result {
                        Ok(v) => v,
                        Err(err) => {
                            // Connection-reset-style errors on UDP
                            // typically come from a previous send_to
                            // hitting a closed port (ICMP port-
                            // unreachable). Logged + continue —
                            // recv_from will resume on subsequent
                            // datagrams.
                            tracing::trace!(
                                target: "rama_apple_ne::tproxy",
                                error = %err,
                                "udp egress recv_from error",
                            );
                            continue;
                        }
                    };
                    let datagram = Datagram {
                        payload: Bytes::copy_from_slice(&buf[..n]),
                        peer: Some(peer),
                    };
                    if inbound_tx.send(datagram).await.is_err() {
                        // Bridge closed; nothing to do.
                        break;
                    }
                }
            }
        }
        tracing::trace!(target: "rama_apple_ne::tproxy", "udp egress recv pump exited");
    });

    Ok(UdpEgress {
        local_addr,
        outbound_tx,
        _send_task: send_task,
        _recv_task: recv_task,
    })
}
