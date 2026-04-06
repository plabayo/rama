use std::{
    io,
    mem::{size_of, zeroed},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, RawFd},
    ptr,
};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsMut,
};

use crate::{address::SocketAddress, proxy::ProxyTarget};

#[derive(Debug, Clone, Default)]
/// Layer to create [`ProxyTargetFromGetSocketname`] middleware.
pub struct ProxyTargetFromGetSocketnameLayer;

impl ProxyTargetFromGetSocketnameLayer {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromGetSocketnameLayer`]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ProxyTargetFromGetSocketnameLayer {
    type Service = ProxyTargetFromGetSocketname<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromGetSocketname { inner }
    }
}

#[derive(Debug, Clone)]
/// Middleware that can be used by Linux transparent proxies,
/// to insert the [`ProxyTarget`] based on the address inserted
/// by the OS in the "socketname" of the underlying OS socket.
///
/// Created using [`ProxyTargetFromGetSocketnameLayer`].
pub struct ProxyTargetFromGetSocketname<S> {
    inner: S,
}

impl<S, Input> Service<Input> for ProxyTargetFromGetSocketname<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawFd + ExtensionsMut + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let proxy_target = proxy_target_from_input(input.as_raw_fd())
            .context("get proxy target from input stream")?;
        input
            .extensions_mut()
            .insert(ProxyTarget(proxy_target.into()));
        self.inner.serve(input).await.context("inner serve tcp")
    }
}

fn proxy_target_from_input(fd: RawFd) -> Result<SocketAddress, BoxError> {
    // SAFETY: `sockaddr_storage` is a plain old data buffer used as out-parameter
    // storage for `getsockname`, so zero-initializing it is valid.
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let rc = unsafe {
        // SAFETY: `fd` comes from `AsRawFd`; `storage` points to a writable
        // `sockaddr_storage` buffer of `len` bytes; and `len` is a valid mutable
        // pointer for the kernel to update with the number of bytes written.
        libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len)
    };

    if rc != 0 {
        return Err(io::Error::last_os_error().context("getsockname"));
    }

    sockaddr_storage_to_socket_addr(&storage, len).context("socketaddr storage to SocketAddress")
}

fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddress> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => parse_sockaddr_in(storage, len),
        libc::AF_INET6 => parse_sockaddr_in6(storage, len),
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported address family: {family}"),
        )),
    }
}

fn parse_sockaddr_in(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddress> {
    ensure_sockaddr_len::<libc::sockaddr_in>(len, "sockaddr_in")?;

    let addr: libc::sockaddr_in = unsafe {
        // SAFETY: the family is `AF_INET` and `ensure_sockaddr_len` verified that at
        // least a full `sockaddr_in` was written. We use `read_unaligned` because
        // `sockaddr_storage` does not guarantee alignment for `sockaddr_in`.
        ptr::read_unaligned((storage as *const libc::sockaddr_storage).cast())
    };
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)).into())
}

fn parse_sockaddr_in6(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddress> {
    ensure_sockaddr_len::<libc::sockaddr_in6>(len, "sockaddr_in6")?;

    let addr: libc::sockaddr_in6 = unsafe {
        // SAFETY: the family is `AF_INET6` and `ensure_sockaddr_len` verified that at
        // least a full `sockaddr_in6` was written. We use `read_unaligned` because
        // `sockaddr_storage` does not guarantee alignment for `sockaddr_in6`.
        ptr::read_unaligned((storage as *const libc::sockaddr_storage).cast())
    };
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
    use super::*;
    use std::{mem::zeroed, net::IpAddr};

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

        let storage = sockaddr_storage_from(raw);
        let addr =
            sockaddr_storage_to_socket_addr(&storage, size_of::<libc::sockaddr_in>() as _).unwrap();

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

        let storage = sockaddr_storage_from(raw);
        let addr = sockaddr_storage_to_socket_addr(&storage, size_of::<libc::sockaddr_in6>() as _)
            .unwrap();

        assert_eq!(addr.ip_addr, IpAddr::V6(ip));
        assert_eq!(addr.port, port);
    }

    #[test]
    fn sockaddr_storage_to_socket_addr_rejects_short_sockaddr() {
        let storage = sockaddr_storage_from(libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        });

        let err = sockaddr_storage_to_socket_addr(&storage, 1).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "short sockaddr_in");
    }

    #[test]
    fn sockaddr_storage_to_socket_addr_rejects_unsupported_family() {
        // SAFETY: `sockaddr_storage` is POD and zero-initialization is valid for a test buffer.
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        storage.ss_family = libc::AF_UNIX as _;

        let err =
            sockaddr_storage_to_socket_addr(&storage, size_of::<libc::sockaddr_storage>() as _)
                .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "unsupported address family: 1");
    }

    fn sockaddr_storage_from<T>(raw: T) -> libc::sockaddr_storage {
        // SAFETY: `sockaddr_storage` is POD and zero-initialization is valid for a test buffer.
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        unsafe {
            // SAFETY: the destination points to stack-allocated storage large enough for
            // the concrete sockaddr value used in the test, and we only read it back as
            // that same concrete type.
            ptr::write(
                (&mut storage as *mut libc::sockaddr_storage).cast::<T>(),
                raw,
            );
        }
        storage
    }
}
