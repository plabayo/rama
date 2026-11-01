//! [`PairedSocket`], in a module of its own so that only its constructor sets its fields.

use std::{
    io::{self, IoSliceMut},
    ops::Deref,
};

use tokio::net::UdpSocket;

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

impl Deref for PairedSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &UdpSocket {
        &self.io
    }
}
