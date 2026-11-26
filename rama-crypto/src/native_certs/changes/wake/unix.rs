#[cfg(target_os = "macos")]
use std::{
    ffi::c_int,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
};
use std::{
    io::{self, Read as _, Write as _},
    os::unix::net::UnixStream,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[cfg(target_os = "macos")]
use crate::native_certs::notifications::StoreNotifications;

pub(crate) struct Wake {
    pub(super) reader: UnixStream,
    pub(super) writer: UnixStream,
    // Set while a wake byte is unread, so the socket holds at most one byte.
    pending: AtomicBool,
}

impl Wake {
    /// A wake that no wait has consumed yet.
    pub(super) fn new() -> io::Result<Self> {
        // std creates both ends close-on-exec.
        let (reader, writer) = UnixStream::pair()?;
        writer.set_nonblocking(true)?;
        // poll(2) reports readiness, so draining must not block.
        #[cfg(target_os = "macos")]
        reader.set_nonblocking(true)?;
        Ok(Self {
            reader,
            writer,
            pending: AtomicBool::new(false),
        })
    }

    /// End the current or next wait early.
    pub(super) fn wake(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) && (&self.writer).write(&[1]).is_err() {
            self.pending.store(false, Ordering::Release);
        }
    }

    // A wake racing with this consumption coalesces into the wait that is returning.
    /// Clear the pending wake after consuming its notification.
    fn consumed(&self) -> bool {
        self.pending.store(false, Ordering::Release);
        true
    }

    /// Returns whether a wake ended the wait, or an error when it could not block at all.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn wait(&self, timeout: Duration) -> io::Result<bool> {
        if timeout.is_zero() {
            return Ok(false);
        }
        self.reader.set_read_timeout(Some(timeout))?;
        match (&self.reader).read(&mut [0; 1]) {
            Ok(read) if read > 0 => Ok(self.consumed()),
            Ok(_) => Ok(false),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Returns whether a wake ended the wait, or an error when it could not block at all.
    #[cfg(target_os = "macos")]
    pub(crate) fn wait(
        &self,
        notifications: Option<&mut StoreNotifications>,
        timeout: Duration,
    ) -> io::Result<bool> {
        let notify_fd = notifications
            .as_deref()
            .and_then(StoreNotifications::wait_fd);
        let [woken, notified] = poll_readable(self.reader.as_fd(), notify_fd, timeout)?;
        if notified && let Some(notifications) = notifications {
            notifications.drain_wait_fd();
        }
        if !woken {
            return Ok(false);
        }
        while matches!((&self.reader).read(&mut [0; 64]), Ok(read) if read > 0) {}
        Ok(self.consumed())
    }
}

/// Wait until `wake` or `notify` is readable or `timeout` passes, reporting which are readable.
#[cfg(target_os = "macos")]
fn poll_readable(
    wake: BorrowedFd<'_>,
    notify: Option<BorrowedFd<'_>>,
    timeout: Duration,
) -> io::Result<[bool; 2]> {
    let mut fds = [
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        // poll(2) ignores negative descriptors.
        libc::pollfd {
            fd: notify.map_or(-1, |fd| fd.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // Round up so the wait never ends just before the next probe is due.
    let millis = c_int::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(c_int::MAX);
    // SAFETY: `fds` holds 2 initialised records for `nfds = 2`; each descriptor is -1
    // (ignored by poll(2)) or a `BorrowedFd` parameter, so it stays open for the call.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        return match error.kind() {
            io::ErrorKind::Interrupted => Ok([false; 2]),
            _ => Err(error),
        };
    }
    Ok(fds.map(|fd| fd.revents != 0))
}
