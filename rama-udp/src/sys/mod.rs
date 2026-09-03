//! Operating-system UDP packet I/O.
//!
//! This module uses Unix control messages and Winsock message APIs to exchange
//! per-packet addresses, Explicit Congestion Notification (ECN), interface,
//! timestamp, truncation, batching and segmentation data. RFC 768 defines the
//! datagrams, RFC 3168 and RFC 8311 define ECN, and RFC 8085 supplies the UDP
//! usage rules enforced by the public types. The module stays private so
//! platform layouts and feature probes do not become part of Rama's API.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

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
}

impl Transmit<'_> {
    fn effective_segment_size(&self) -> Option<usize> {
        match self.segment_size? {
            size if size >= self.contents.len() => None,
            size => Some(size),
        }
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
