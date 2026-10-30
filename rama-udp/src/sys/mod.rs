//! Operating-system UDP packet I/O.
//!
//! This module uses Unix control messages and Winsock message APIs to exchange
//! per-packet addresses, Explicit Congestion Notification (ECN), interface,
//! timestamp, truncation, batching and segmentation data. RFC 768 defines the
//! datagrams, RFC 3168 and RFC 8311 define ECN, and RFC 8085 supplies the UDP
//! usage rules enforced by the public types. The module stays private so
//! platform layouts and feature probes do not become part of Rama's API.

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(not(windows))]
use std::io::IoSliceMut;
use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ops::Deref,
    time::Duration,
};

use tokio::net::UdpSocket;

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;

use crate::EcnCodepoint;

#[cfg(any(unix, windows))]
mod cmsg;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

#[cfg(not(any(all(target_family = "wasm", target_os = "unknown"), unix, windows)))]
#[path = "fallback.rs"]
mod imp;

pub(crate) use imp::UdpSocketState;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use imp::set_socket_option;
pub(crate) const BATCH_SIZE: usize = imp::BATCH_SIZE;

#[derive(Debug, Copy, Clone)]
pub(crate) struct SocketCapabilities {
    pub(crate) send_ecn: bool,
    pub(crate) receive_ecn: bool,
    pub(crate) send_source_ip: bool,
    pub(crate) receive_local_ip: bool,
    pub(crate) receive_interface: bool,
    pub(crate) receive_original_destination: bool,
    pub(crate) receive_timestamp: bool,
    pub(crate) receive_truncation: bool,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct RecvMeta {
    pub(crate) addr: SocketAddr,
    pub(crate) len: usize,
    pub(crate) original_len: usize,
    pub(crate) stride: usize,
    pub(crate) ecn: Option<EcnCodepoint>,
    pub(crate) dst_ip: Option<IpAddr>,
    pub(crate) interface_index: Option<u32>,
    pub(crate) original_destination: Option<SocketAddr>,
    pub(crate) timestamp: Option<Duration>,
    pub(crate) truncated: bool,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            original_len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            interface_index: None,
            original_destination: None,
            timestamp: None,
            truncated: false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Transmit<'a> {
    pub(crate) destination: SocketAddr,
    pub(crate) ecn: Option<EcnCodepoint>,
    pub(crate) contents: &'a [u8],
    pub(crate) segment_size: Option<usize>,
    pub(crate) src_ip: Option<IpAddr>,
    /// The IPv6 zone of `src_ip`, as the outgoing interface.
    pub(crate) src_interface: Option<u32>,
}

impl Transmit<'_> {
    fn effective_segment_size(&self) -> Option<usize> {
        match self.segment_size? {
            size if size >= self.contents.len() => None,
            size => Some(size),
        }
    }
}

/// A socket together with the platform state created for it.
///
/// Receives and sends go through this pairing: Windows state holds entry points that
/// belong to the provider of the socket it was created for.
#[derive(Debug)]
pub(crate) struct PairedSocket {
    // Safety invariant: `state` was created by `UdpSocketState::new` for this `io`, which
    // stays open and is never replaced while `state` lives.
    io: UdpSocket,
    state: UdpSocketState,
}

impl PairedSocket {
    pub(crate) fn new(io: UdpSocket, receive_original_destination: bool) -> io::Result<Self> {
        let state = UdpSocketState::new((&io).into(), receive_original_destination)?;
        // Safety invariant: `state` was just created for `io`, and both move in together.
        Ok(Self { io, state })
    }

    pub(crate) fn state(&self) -> &UdpSocketState {
        &self.state
    }
}

// Windows defines these next to its state, whose receive and send are `unsafe fn`.
#[cfg(not(windows))]
impl PairedSocket {
    pub(crate) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        self.state.recv(&(&self.io).into(), bufs, meta)
    }

    pub(crate) fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.state.try_send(&(&self.io).into(), transmit)
    }
}

impl Deref for PairedSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &UdpSocket {
        &self.io
    }
}

pub(crate) struct UdpSockRef<'a>(rama_net::socket::core::SockRef<'a>);

#[cfg(unix)]
impl<'socket, S> From<&'socket S> for UdpSockRef<'socket>
where
    S: AsFd,
{
    fn from(socket: &'socket S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'socket, S> From<&'socket S> for UdpSockRef<'socket>
where
    S: AsSocket,
{
    fn from(socket: &'socket S) -> Self {
        Self(socket.into())
    }
}

/// Whether `destination` is the peer a connected socket is fixed to. Such a send names no
/// destination: some platforms refuse an explicit one on a connected socket.
pub(crate) fn is_connected_peer(connected: Option<SocketAddr>, destination: SocketAddr) -> bool {
    let canonical = |address: SocketAddr| match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), v6.port()),
            None => address,
        },
        SocketAddr::V4(_) => address,
    };
    connected.is_some_and(|peer| canonical(peer) == canonical(destination))
}
