use std::{sync::Arc, time::Duration};

use parking_lot::RwLock;
use rama_core::extensions::Extensions;
use rama_net::{conn::ConnectionAbort, socket::core::SockRef};

#[cfg(target_os = "windows")]
type RawSocket = std::os::windows::io::RawSocket;
#[cfg(target_family = "unix")]
type RawSocket = std::os::fd::RawFd;

/// Holds the socket a [`ConnectionAbort`] acts on, and lets go of it before
/// the socket is closed. The capability can be cloned anywhere and outlive
/// the stream, so it must never touch a closed, possibly reused, socket
/// handle.
pub(super) struct AbortGuard {
    socket: Arc<RwLock<Option<RawSocket>>>,
    handle: ConnectionAbort,
}

impl AbortGuard {
    pub(super) fn new(socket: RawSocket, extensions: Option<&Extensions>) -> Self {
        let socket = Arc::new(RwLock::new(Some(socket)));
        let weak = Arc::downgrade(&socket);
        let handle = ConnectionAbort::new(move || {
            let Some(socket) = weak.upgrade() else {
                return Ok(());
            };
            let socket = socket.read();
            let Some(raw) = *socket else {
                return Ok(());
            };
            // SAFETY: the guard holds the socket only while it is open, and
            // the read lock keeps the guard from letting go of it meanwhile.
            let borrowed = unsafe { borrow(raw) };
            SockRef::from(&borrowed).set_linger(Some(Duration::ZERO))
        });
        if let Some(extensions) = extensions {
            extensions.insert(handle.clone());
        }
        Self { socket, handle }
    }

    pub(super) fn handle(&self) -> ConnectionAbort {
        self.handle.clone()
    }

    /// Let go of the socket; waits for an abort in progress.
    pub(super) fn release(&self) {
        *self.socket.write() = None;
    }
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// # Safety
///
/// `raw` must stay open for as long as the returned value is used.
#[cfg(target_os = "windows")]
unsafe fn borrow<'a>(raw: RawSocket) -> std::os::windows::io::BorrowedSocket<'a> {
    // SAFETY: per the caller.
    unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(raw) }
}

/// # Safety
///
/// `raw` must stay open for as long as the returned value is used.
#[cfg(target_family = "unix")]
unsafe fn borrow<'a>(raw: RawSocket) -> std::os::fd::BorrowedFd<'a> {
    // SAFETY: per the caller.
    unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) }
}
