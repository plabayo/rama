use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, RawFd},
    ptr,
};

use crate::{address::SocketAddress, client::ConnectorTarget};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsRef,
};

#[derive(Debug, Clone, Default)]
/// Layer to create [`ConnectorTargetFromGetSocketname`] middleware.
pub struct ConnectorTargetFromGetSocketnameLayer;

impl ConnectorTargetFromGetSocketnameLayer {
    #[inline(always)]
    /// Create a new [`ConnectorTargetFromGetSocketnameLayer`]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ConnectorTargetFromGetSocketnameLayer {
    type Service = ConnectorTargetFromGetSocketname<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectorTargetFromGetSocketname { inner }
    }
}

#[derive(Debug, Clone)]
/// Middleware that can be used by Linux transparent proxies,
/// to insert the [`ConnectorTarget`] based on the address inserted
/// by the OS in the "socketname" of the underlying OS socket.
///
/// Created using [`ConnectorTargetFromGetSocketnameLayer`].
pub struct ConnectorTargetFromGetSocketname<S> {
    inner: S,
}

impl<S, Input> Service<Input> for ConnectorTargetFromGetSocketname<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawFd + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let proxy_target = connector_target_from_input(input.as_raw_fd())
            .context("get (proxy) connector target from input stream")?;
        input
            .extensions()
            .insert(ConnectorTarget(proxy_target.into()));
        self.inner.serve(input).await.context("inner serve tcp")
    }
}

/// Byte copy of a `sockaddr_storage`.
type SockaddrBytes = [u8; size_of::<libc::sockaddr_storage>()];

/// Output buffer for `getsockname`, aligned for every sockaddr type.
#[repr(C)]
union SockaddrBuf {
    storage: libc::sockaddr_storage,
    bytes: SockaddrBytes,
}

fn connector_target_from_input(fd: RawFd) -> Result<SocketAddress, BoxError> {
    let mut buf = SockaddrBuf {
        bytes: [0; size_of::<libc::sockaddr_storage>()],
    };
    let mut len = size_of::<SockaddrBuf>() as libc::socklen_t;

    // SAFETY: getsockname(2) writes at most `len` bytes of address to its
    // second argument and the actual length to `*len`; any `fd` value is
    // accepted (an invalid one fails with EBADF/ENOTSOCK) and no fd state is
    // changed. `buf` is a live, writable local of `len` bytes, aligned for
    // `sockaddr` (`sockaddr_storage` member), and `len` is a live `socklen_t`.
    let rc = unsafe { libc::getsockname(fd, (&raw mut buf).cast(), &raw mut len) };

    if rc != 0 {
        return Err(io::Error::last_os_error().context("getsockname"));
    }

    // SAFETY: a union field read needs bytes valid for `[u8; N]`, i.e.
    // initialized: `buf` was created through `bytes` (all zero) and
    // getsockname(2) only stored initialized address bytes into it.
    let bytes = unsafe { buf.bytes };
    sockaddr_bytes_to_socket_addr(&bytes, len).context("socketaddr storage to SocketAddress")
}

fn sockaddr_bytes_to_socket_addr(
    bytes: &SockaddrBytes,
    len: libc::socklen_t,
) -> io::Result<SocketAddress> {
    const FAMILY: usize = std::mem::offset_of!(libc::sockaddr_storage, ss_family);
    let family = libc::sa_family_t::from_ne_bytes([bytes[FAMILY], bytes[FAMILY + 1]]);
    match libc::c_int::from(family) {
        libc::AF_INET => parse_sockaddr_in(bytes, len),
        libc::AF_INET6 => parse_sockaddr_in6(bytes, len),
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported address family: {family}"),
        )),
    }
}

fn parse_sockaddr_in(bytes: &SockaddrBytes, len: libc::socklen_t) -> io::Result<SocketAddress> {
    ensure_sockaddr_len::<libc::sockaddr_in>(len, "sockaddr_in")?;

    const { assert!(size_of::<libc::sockaddr_in>() <= size_of::<SockaddrBytes>()) };
    // SAFETY: `read_unaligned` needs `size_of::<sockaddr_in>()` readable bytes
    // holding a valid `sockaddr_in`, without alignment. The const assert keeps
    // the read inside `*bytes`, initialized as `[u8]`; `sockaddr_in` has
    // integer and integer-array fields only, so any initialized bytes are valid.
    let addr: libc::sockaddr_in = unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) };
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)).into())
}

fn parse_sockaddr_in6(bytes: &SockaddrBytes, len: libc::socklen_t) -> io::Result<SocketAddress> {
    ensure_sockaddr_len::<libc::sockaddr_in6>(len, "sockaddr_in6")?;

    const { assert!(size_of::<libc::sockaddr_in6>() <= size_of::<SockaddrBytes>()) };
    // SAFETY: as in `parse_sockaddr_in`, for `sockaddr_in6`, which also has
    // integer and integer-array fields only.
    let addr: libc::sockaddr_in6 = unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) };
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);

    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip,
        port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    ))
    .into())
}

fn ensure_sockaddr_len<T>(len: libc::socklen_t, kind: &'static str) -> io::Result<()> {
    if len < size_of::<T>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short {kind}"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn sockaddr_storage_to_socket_addr_ipv4() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 15001u16;
        let raw = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        };

        // SAFETY: `sockaddr_in` has integer and integer-array fields only and
        // no padding (2 + 2 + 4 + 8 bytes = its size).
        let storage = unsafe { sockaddr_bytes_from(raw) };
        let addr =
            sockaddr_bytes_to_socket_addr(&storage, size_of::<libc::sockaddr_in>() as _).unwrap();

        assert_eq!(addr.ip_addr, IpAddr::V4(ip));
        assert_eq!(addr.port, port);
    }

    #[test]
    fn sockaddr_storage_to_socket_addr_ipv6() {
        let ip = Ipv6Addr::LOCALHOST;
        let port = 15001u16;
        let flowinfo = 42;
        let scope_id = 7;
        let raw = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as _,
            sin6_port: port.to_be(),
            sin6_flowinfo: flowinfo,
            sin6_addr: libc::in6_addr {
                s6_addr: ip.octets(),
            },
            sin6_scope_id: scope_id,
        };

        // SAFETY: `sockaddr_in6` has integer and integer-array fields only and
        // no padding (2 + 2 + 4 + 16 + 4 bytes = its size).
        let storage = unsafe { sockaddr_bytes_from(raw) };
        let addr =
            sockaddr_bytes_to_socket_addr(&storage, size_of::<libc::sockaddr_in6>() as _).unwrap();

        assert_eq!(addr.ip_addr, IpAddr::V6(ip));
        assert_eq!(addr.port, port);
    }

    #[test]
    fn sockaddr_storage_to_socket_addr_rejects_short_sockaddr() {
        // SAFETY: as in `sockaddr_storage_to_socket_addr_ipv4`.
        let storage = unsafe {
            sockaddr_bytes_from(libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            })
        };

        let err = sockaddr_bytes_to_socket_addr(&storage, 1).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "short sockaddr_in");
    }

    #[test]
    fn sockaddr_storage_to_socket_addr_rejects_unsupported_family() {
        let mut storage: SockaddrBytes = [0; size_of::<libc::sockaddr_storage>()];
        storage[..2].copy_from_slice(&(libc::AF_UNIX as libc::sa_family_t).to_ne_bytes());

        let err = sockaddr_bytes_to_socket_addr(&storage, size_of::<libc::sockaddr_storage>() as _)
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "unsupported address family: 1");
    }

    #[test]
    fn connector_target_from_bound_sockets() {
        let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = connector_target_from_input(v4.as_raw_fd()).unwrap();
        assert_eq!(SocketAddr::from(addr), v4.local_addr().unwrap());

        if let Ok(v6) = std::net::TcpListener::bind("[::1]:0") {
            let addr = connector_target_from_input(v6.as_raw_fd()).unwrap();
            assert_eq!(SocketAddr::from(addr), v6.local_addr().unwrap());
        }

        let not_a_socket = std::fs::File::open("/dev/null").unwrap();
        connector_target_from_input(not_a_socket.as_raw_fd()).unwrap_err();
    }

    /// The bytes of `raw` at the start of an otherwise zeroed buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `T` has no padding bytes, so that all
    /// `size_of::<T>()` bytes of `raw` are initialized.
    unsafe fn sockaddr_bytes_from<T: Copy>(raw: T) -> SockaddrBytes {
        const { assert!(size_of::<T>() <= size_of::<SockaddrBytes>()) };
        let mut bytes: SockaddrBytes = [0; size_of::<libc::sockaddr_storage>()];
        // SAFETY: `write_unaligned` needs `size_of::<T>()` writable bytes, with
        // no alignment: the const assert keeps them inside `bytes`. The caller
        // guarantees `raw` has no padding, so `bytes` stays initialized.
        unsafe { bytes.as_mut_ptr().cast::<T>().write_unaligned(raw) };
        bytes
    }
}
