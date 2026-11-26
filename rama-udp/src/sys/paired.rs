//! [`PairedSocket`], in a module of its own so that only its constructor sets its fields.

use std::{
    io::{self, IoSliceMut},
    ops::Deref,
};

use rama_net::ip::icmp::IcmpErrorReport;
use tokio::net::UdpSocket;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::linux::errqueue;

use super::{RecvMeta, Transmit, UdpSocketState};

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

    #[cfg(not(windows))]
    pub(crate) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        self.state.recv(&(&self.io).into(), bufs, meta)
    }

    #[cfg(not(windows))]
    pub(crate) fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.state.try_send(&(&self.io).into(), transmit)
    }

    #[cfg(windows)]
    pub(crate) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // SAFETY: `recv` needs the open socket the state was created for: `self.io`, by
        // the field invariant, borrowed for the call.
        unsafe { self.state.recv(&(&self.io).into(), bufs, meta) }
    }

    #[cfg(windows)]
    pub(crate) fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // SAFETY: `try_send` needs the open socket the state was created for: `self.io`, by
        // the field invariant, borrowed for the call.
        unsafe { self.state.try_send(&(&self.io).into(), transmit) }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl PairedSocket {
    /// Hold the error queue on for one more ICMP error receiver.
    pub(crate) fn acquire_icmp_reports(&self) -> io::Result<()> {
        self.state.icmp_reports().acquire(&self.io)
    }

    /// Release what [`Self::acquire_icmp_reports`] took.
    pub(crate) fn release_icmp_reports(&self) {
        self.state.icmp_reports().release(&self.io);
    }

    /// The next queued report, or `WouldBlock`.
    pub(crate) fn recv_icmp_report(&self) -> io::Result<IcmpErrorReport> {
        errqueue::recv(&self.io)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[expect(
    clippy::unused_self,
    reason = "the same methods as on Linux, where the socket holds the error queue"
)]
impl PairedSocket {
    /// Refused: ICMP error reports need the Linux socket error queue.
    pub(crate) fn acquire_icmp_reports(&self) -> io::Result<()> {
        Err(icmp_reports_unsupported())
    }

    /// Nothing can be acquired, so nothing is released.
    pub(crate) fn release_icmp_reports(&self) {}

    /// Refused, as [`Self::acquire_icmp_reports`] is.
    pub(crate) fn recv_icmp_report(&self) -> io::Result<IcmpErrorReport> {
        Err(icmp_reports_unsupported())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn icmp_reports_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "ICMP error reports need the Linux socket error queue",
    )
}

impl Deref for PairedSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &UdpSocket {
        &self.io
    }
}
