//! Inspect the network sockets owned by a process.
//!
//! These synchronous OS queries return snapshots, not process identities or
//! authorization decisions: a process can exit and its PID can be reused.
//! Retain a child/process handle and check its lifetime when identifying a child.

use crate::transport::TransportProtocol;
use std::{io, net::SocketAddr};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;

/// A TCP listener or bound UDP endpoint owned by a process.
///
/// UDP has no listening state. Its entries include connected UDP sockets;
/// observing a bound socket does not establish application readiness.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessSocket {
    /// The socket's transport protocol.
    pub protocol: TransportProtocol,
    /// The local address reported by the OS, including IPv6 scope when supplied.
    ///
    /// Windows may report a connected UDP socket's original wildcard bind
    /// address, even after connecting selects a concrete local address.
    pub local_addr: SocketAddr,
}

/// Query TCP listeners and bound UDP endpoints owned by `pid`.
///
/// The result is sorted and deduplicated (multiple descriptors can refer to the
/// same endpoint). TCP connections and unbound UDP sockets are excluded. This
/// does not follow child processes or identify the application role of a socket.
/// Inherited sockets are included; during process startup, these can appear
/// briefly before the child closes descriptors marked close-on-exec.
///
/// Supported on Linux, macOS and Windows. Other platforms return
/// [`io::ErrorKind::Unsupported`]. Access restrictions are returned as errors,
/// not an empty result. Sockets can disappear during enumeration, and a process
/// can exit immediately after the query; a snapshot is not a reservation.
///
/// Linux joins the process's socket descriptors to its network namespace's
/// `/proc` tables. Sockets moved between network namespaces may not be visible.
/// Those tables do not expose IPv6 scope IDs, so Linux reports scope zero.
/// macOS uses libproc and Windows uses the owner-PID IP Helper tables. These
/// calls may block; use a blocking executor when calling from async code.
pub fn listening_sockets(pid: u32) -> io::Result<Vec<ProcessSocket>> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process ID",
        ));
    }

    let mut sockets = platform::listening_sockets(pid)?;
    sockets.sort_unstable();
    sockets.dedup();

    Ok(sockets)
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tests;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;

    pub(super) fn listening_sockets(_pid: u32) -> io::Result<Vec<ProcessSocket>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process socket inspection is unavailable on this platform",
        ))
    }
}
