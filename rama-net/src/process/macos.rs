use super::{ProcessSocket, TransportProtocol};
use std::{
    io,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

const DESCRIPTOR_HEADROOM: usize = 32;
const MAX_DESCRIPTOR_ATTEMPTS: usize = 8;

/// Mirrors `struct rama_net_socket_info` in `macos.c`; both sides assert the layout.
#[repr(C)]
#[derive(Default)]
struct SocketInfo {
    address: [u8; 16],
    scope: u32,
    port: u16,
    version: u8,
    protocol: u8,
}

const _: () = {
    assert!(size_of::<SocketInfo>() == 24);
    assert!(offset_of!(SocketInfo, scope) == 16);
    assert!(offset_of!(SocketInfo, port) == 20);
    assert!(offset_of!(SocketInfo, version) == 22);
    assert!(offset_of!(SocketInfo, protocol) == 23);
};

unsafe extern "C" {
    /// Describe descriptor `fd` of process `pid` (see `macos.c`).
    ///
    /// # Safety
    ///
    /// The caller must ensure `info` is non-null, aligned for `SocketInfo` and
    /// valid for writes of `size_of::<SocketInfo>()` bytes for the call. Any
    /// `pid` and `fd` value is accepted. On a return of `1` the shim has fully
    /// written `*info`; otherwise its content is unspecified.
    fn rama_net_pid_socket(pid: i32, fd: i32, info: *mut SocketInfo) -> i32;
}

pub(super) fn listening_sockets(pid: u32) -> io::Result<Vec<ProcessSocket>> {
    let mut sockets = Vec::new();

    for fd in socket_descriptors(pid)? {
        if let Some(socket) = inspect_socket(pid, fd)? {
            sockets.push(socket);
        }
    }

    Ok(sockets)
}

fn socket_descriptors(pid: u32) -> io::Result<Vec<i32>> {
    let needed = read_descriptors(pid, &mut [])?;
    let mut count = needed / size_of::<libc::proc_fdinfo>() + DESCRIPTOR_HEADROOM;

    // Leave room for newly opened descriptors, but bound retries under churn.
    for _ in 0..MAX_DESCRIPTOR_ATTEMPTS {
        let mut fds: Vec<libc::proc_fdinfo> = (0..count)
            .map(|_| libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            })
            .collect();
        let written = read_descriptors(pid, &mut fds)?;

        if written == fds.len() * size_of::<libc::proc_fdinfo>() {
            count *= 2;
            continue;
        }
        fds.truncate(written / size_of::<libc::proc_fdinfo>());

        return Ok(fds
            .into_iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .map(|fd| fd.proc_fd)
            .collect());
    }

    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "process descriptor table kept growing",
    ))
}

/// An empty buffer queries the required size; otherwise read into the buffer.
fn read_descriptors(pid: u32, fds: &mut [libc::proc_fdinfo]) -> io::Result<usize> {
    let bytes = std::mem::size_of_val(fds);
    let buffer_size = i32::try_from(bytes).map_err(|error| {
        io::Error::other(format!("process descriptor table too large: {error}"))
    })?;
    let buffer = if fds.is_empty() {
        std::ptr::null_mut()
    } else {
        fds.as_mut_ptr().cast()
    };

    // libproc returns zero for both an error and an empty descriptor list.
    // Clear the calling thread's errno so a successful empty read is distinct.
    // SAFETY: Darwin `<sys/errno.h>` defines `errno` as `*__error()`; the call
    // has no preconditions and returns this thread's errno location.
    let errno = unsafe { libc::__error() };
    // SAFETY: by that definition `errno` is a non-null, aligned, writable
    // `c_int` owned by the current thread for its whole lifetime.
    unsafe { errno.write(0) };

    // SAFETY: libproc `proc_pidinfo` writes at most `buffersize` bytes to
    // `buffer`, and with a null buffer only reports the size. `buffer` is
    // either null with `buffer_size == 0`, or `fds`, an exclusively borrowed
    // slice that is aligned for `proc_fdinfo` and exactly `buffer_size` bytes
    // long. `pid` is any `c_int` for libproc; the entry point keeps it lossless.
    let written =
        unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDLISTFDS, 0, buffer, buffer_size) };
    let error = io::Error::last_os_error();
    if written < 0 || (written == 0 && error.raw_os_error() != Some(0)) {
        return Err(error);
    }

    let written = written as usize;
    if (!fds.is_empty() && written > bytes)
        || !written.is_multiple_of(size_of::<libc::proc_fdinfo>())
    {
        return Err(io::Error::other("invalid process descriptor table size"));
    }

    Ok(written)
}

fn inspect_socket(pid: u32, fd: i32) -> io::Result<Option<ProcessSocket>> {
    let mut info = SocketInfo::default();

    // SAFETY: `rama_net_pid_socket` contract: `&raw mut info` is a non-null,
    // aligned, exclusive `SocketInfo` valid for writes during the call, and its
    // layout matches the C record by the compile-time asserts on both sides.
    let result = unsafe { rama_net_pid_socket(pid as i32, fd, &raw mut info) };
    match result {
        // A descriptor may close or cease to be a relevant socket after listing.
        0 => Ok(None),
        1 => info.into_socket().map(Some),
        error => Err(io::Error::from_raw_os_error(-error)),
    }
}

impl SocketInfo {
    fn into_socket(self) -> io::Result<ProcessSocket> {
        let protocol = match self.protocol {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            _ => return Err(io::Error::other("invalid process socket protocol")),
        };

        let local_addr = match self.version {
            4 => SocketAddr::from((
                Ipv4Addr::new(
                    self.address[0],
                    self.address[1],
                    self.address[2],
                    self.address[3],
                ),
                self.port,
            )),
            6 => SocketAddrV6::new(Ipv6Addr::from(self.address), self.port, 0, self.scope).into(),
            _ => return Err(io::Error::other("invalid process socket family")),
        };

        Ok(ProcessSocket {
            protocol,
            local_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::tests::ChildGuard;
    use std::{
        process::Command,
        time::{Duration, Instant},
    };

    #[test]
    fn a_process_without_descriptors_returns_an_empty_snapshot() {
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::macos::tests::descriptorless_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("RAMA_DESCRIPTORLESS_TEST_CHILD", "1")
                .spawn()
                .unwrap(),
        );

        let mut fds: Vec<_> = (0..128)
            .map(|_| libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(child.0.try_wait().unwrap().is_none());

            // A stale error from an earlier syscall must not turn a successful
            // empty read into a failure.
            // SAFETY: `__error` has no preconditions and returns this thread's
            // errno location (Darwin `<sys/errno.h>`).
            let errno = unsafe { libc::__error() };
            // SAFETY: that location is a non-null, aligned, writable `c_int`
            // owned by the current thread.
            unsafe { errno.write(libc::EBADF) };

            if read_descriptors(child.0.id(), &mut fds).unwrap() == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "child retained descriptors");
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(listening_sockets(child.0.id()).unwrap().is_empty());
    }

    #[test]
    #[ignore = "subprocess fixture for the empty descriptor snapshot test"]
    fn descriptorless_child() {
        if std::env::var_os("RAMA_DESCRIPTORLESS_TEST_CHILD").is_none() {
            return;
        }

        // Close after exec: the loader or executable can reopen descriptors
        // closed by pre_exec, and the test runner may inherit more than stdio.
        // SAFETY: getdtablesize has no preconditions.
        let limit = unsafe { libc::getdtablesize() };
        for fd in 0..limit {
            // SAFETY: this disposable child no longer uses any descriptors.
            let _closed = unsafe { libc::close(fd) };
        }
        loop {
            // SAFETY: pause waits for a signal without touching descriptors.
            unsafe { libc::pause() };
        }
    }
}
