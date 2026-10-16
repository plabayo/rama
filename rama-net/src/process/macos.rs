use super::{ProcessSocket, TransportProtocol};
use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

const DESCRIPTOR_HEADROOM: usize = 32;
const MAX_DESCRIPTOR_ATTEMPTS: usize = 8;

#[repr(C)]
#[derive(Default)]
struct SocketInfo {
    address: [u8; 16],
    scope: u32,
    port: u16,
    version: u8,
    protocol: u8,
}

unsafe extern "C" {
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
    // SAFETY: __error returns this thread's valid errno pointer.
    let errno = unsafe { libc::__error() };
    // SAFETY: errno is writable and belongs to the current thread.
    unsafe { errno.write(0) };

    // SAFETY: pid is validated by the public entry point. A null buffer queries
    // size; otherwise the initialized slice is aligned and writable for bytes.
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

    // SAFETY: info is a writable record matching the C shim's layout.
    // The shim validates the SDK query result before copying fields.
    let result = unsafe { rama_net_pid_socket(pid as i32, fd, &mut info) };
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
        os::unix::process::CommandExt as _,
        process::Command,
        time::{Duration, Instant},
    };

    #[test]
    fn a_process_without_descriptors_returns_an_empty_snapshot() {
        fn close_standard_streams() -> io::Result<()> {
            for fd in 0..=2 {
                // SAFETY: this runs only in the child before exec; close is
                // async-signal-safe and these descriptors are no longer needed.
                let _closed = unsafe { libc::close(fd) };
            }
            Ok(())
        }

        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        // SAFETY: the callback only closes descriptors, without allocation or
        // synchronization. It does not affect the parent test's streams.
        unsafe { command.pre_exec(close_standard_streams) };
        let mut child = ChildGuard(command.spawn().unwrap());

        let mut fds: Vec<_> = (0..128)
            .map(|_| libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(child.0.try_wait().unwrap().is_none());

            // A stale error from an earlier syscall must not turn a successful
            // empty read into a failure.
            // SAFETY: __error returns this thread's valid errno pointer.
            let errno = unsafe { libc::__error() };
            // SAFETY: this thread owns the writable errno value.
            unsafe { errno.write(libc::EBADF) };

            if read_descriptors(child.0.id(), &mut fds).unwrap() == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "sleep retained descriptors");
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(listening_sockets(child.0.id()).unwrap().is_empty());
    }
}
