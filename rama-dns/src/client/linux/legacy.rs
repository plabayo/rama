use std::ffi::CStr;
use std::{
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    time::Duration,
};

use ahash::{HashSet, HashSetExt as _};
use libc::{
    AF_INET, AF_INET6, SOCK_STREAM, addrinfo, c_int, in_addr, in6_addr, sockaddr_in, sockaddr_in6,
};
use rama_core::{
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, LookupEvent, NativeConfig, dns_name_from_domain};
use crate::client::limit::{DnsTimeoutError, deadline_after};

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    lookup_address_stream(domain, timeout, native, lookup_addresses_impl::<Ipv4Addr>)
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    lookup_address_stream(domain, timeout, native, lookup_addresses_impl::<Ipv6Addr>)
}

fn lookup_address_stream<T, F>(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
    lookup: F,
) -> impl Stream<Item = Result<LookupEvent<T>, BoxError>> + Send
where
    T: FromSockAddr + Send + 'static + std::fmt::Debug,
    F: FnOnce(&Domain, &mpsc::Sender<Result<LookupEvent<T>, BoxError>>) -> Result<(), BoxError>
        + Send
        + 'static,
{
    stream_fn(async move |mut yielder| {
        let family = T::FAMILY;
        tracing::debug!(?timeout, %domain, family, "dns::linux: getaddrinfo query");

        let deadline = deadline_after(timeout);
        let (tx, mut rx) = mpsc::channel(8);
        let task = native.limit.spawn_blocking(deadline, move |budget| {
            if budget.is_zero() {
                return Err(DnsTimeoutError::new(timeout).into());
            }
            lookup(&domain, &tx)
        });
        let Some(join) = task.await else {
            tracing::debug!("linux::getaddrinfo: no native lookup slot before the deadline");
            yielder
                .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                .await;
            return;
        };

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(item)) => yielder.yield_item(item).await,
                Ok(None) => break,
                Err(err) => {
                    tracing::debug!(
                        %err,
                        "linux::getaddrinfo: item failed to resolve on time: return timeout error",
                    );
                    // `getaddrinfo` is a blocking libc call, so timing out here only stops
                    // waiting for the worker result; it does not cancel the underlying OS
                    // resolver call once it has started.
                    yielder
                        .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                        .await;
                    return;
                }
            }
        }

        match join.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                yielder.yield_item(Err(err)).await;
            }
            Err(err) => {
                yielder
                    .yield_item(Err(LinuxDnsResolverError::message(format!(
                        "linux dns blocking task failed: {err}"
                    ))
                    .into()))
                    .await;
            }
        }
    })
}

fn lookup_addresses_impl<T>(
    domain: &Domain,
    tx: &mpsc::Sender<Result<LookupEvent<T>, BoxError>>,
) -> Result<(), BoxError>
where
    T: FromSockAddr,
{
    let name = dns_name_from_domain(domain.as_str())?;

    let hints = addrinfo {
        ai_flags: libc::AI_ADDRCONFIG,
        ai_family: T::FAMILY,
        ai_socktype: SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };

    let mut result: *mut addrinfo = ptr::null_mut();
    // SAFETY: getaddrinfo(3) needs a NUL-terminated node name or null, a
    // service name or null, hints or null whose other members are 0 or null,
    // and a writable result pointer: `name` is a `CString`, the service is
    // null, `hints` sets only flags, family and socket type, and `result` is
    // a local. On success it stores a list to free with freeaddrinfo(3).
    let status = unsafe {
        libc::getaddrinfo(
            name.as_ptr(),
            ptr::null(),
            &raw const hints,
            &raw mut result,
        )
    };
    if status != 0 {
        // SAFETY: `gai_strerror` takes any status code.
        let message = unsafe { libc::gai_strerror(status) };
        // SAFETY: gai_strerror(3) returns a NUL-terminated message that stays
        // valid and unmodified at least until the next call on this thread;
        // it is copied out before any other call.
        let message = unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned();
        return Err(
            LinuxDnsResolverError::message(format!("getaddrinfo failed: {message}")).into(),
        );
    }

    // Safety invariant of `AddrInfoGuard`: `result` is the list getaddrinfo
    // just returned, not freed yet, owned by the guard from here on.
    let _guard = AddrInfoGuard(result);
    let mut seen = HashSet::new();
    let mut current = result;

    while !current.is_null() {
        // SAFETY: reference creation: per getaddrinfo(3) the list is a chain
        // of initialized `addrinfo` structures linked through `ai_next`,
        // allocated by libc and valid until freeaddrinfo(3), which only
        // `_guard` calls, after this loop. Nothing writes them meanwhile.
        let current_ref = unsafe { &*current };
        // The address length is `socklen_t`, a `u32`.
        if current_ref.ai_family == T::FAMILY
            && !current_ref.ai_addr.is_null()
            && (current_ref.ai_addrlen as usize) >= size_of::<T::SockAddr>()
        {
            // SAFETY: the `from_sockaddr` contract: per getaddrinfo(3)
            // `ai_addr` points to a socket address of family `ai_family` and
            // length `ai_addrlen`, written by libc and valid until the list
            // is freed; the family and the length were checked just above.
            let addr = unsafe { T::from_sockaddr(current_ref.ai_addr.cast_const().cast()) };
            // `getaddrinfo` does not expose per-record TTL — the cache layer
            // treats `None` as "unknown, fall back to the configured default".
            //
            // Note: we deliberately do not emit `AuthoritativeNegative` from
            // this backend even when the result set is empty, because
            // `AI_ADDRCONFIG` (set in the hints above) can suppress an entire
            // family on a host that lacks v4/v6 connectivity. A locally
            // suppressed family is not a DNS negative and must not poison the
            // cache.
            if seen.insert(addr.clone_key())
                && tx
                    .blocking_send(Ok(LookupEvent::Record(addr, None)))
                    .is_err()
            {
                break;
            }
        }
        current = current_ref.ai_next;
    }

    Ok(())
}

/// An IP address read out of a `getaddrinfo` result of its family.
trait FromSockAddr: Sized {
    /// The `AF_*` family of the addresses this reads.
    const FAMILY: c_int;
    /// The socket address type of that family.
    type SockAddr;
    type Key: Eq + std::hash::Hash;

    /// Read the IP address out of a socket address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `addr` points to a socket address of
    /// family [`Self::FAMILY`] whose first `size_of::<Self::SockAddr>()`
    /// bytes are readable and within one allocation for the duration of the
    /// call, with the address field initialized. `addr` need not be aligned.
    unsafe fn from_sockaddr(addr: *const Self::SockAddr) -> Self;
    fn clone_key(&self) -> Self::Key;
}

impl FromSockAddr for Ipv4Addr {
    const FAMILY: c_int = AF_INET;
    type SockAddr = sockaddr_in;
    type Key = Self;

    unsafe fn from_sockaddr(addr: *const sockaddr_in) -> Self {
        let field = addr
            .wrapping_byte_add(offset_of!(sockaddr_in, sin_addr))
            .cast::<in_addr>();
        // SAFETY: `ptr::read_unaligned`: `sin_addr` lies within the readable
        // `sockaddr_in` (this function's contract), is initialized, and an
        // `in_addr` is a `u32`, valid for any initialized bytes.
        let addr = unsafe { field.read_unaligned() };
        Self::from(addr.s_addr.to_ne_bytes())
    }

    fn clone_key(&self) -> Self::Key {
        *self
    }
}

impl FromSockAddr for Ipv6Addr {
    const FAMILY: c_int = AF_INET6;
    type SockAddr = sockaddr_in6;
    type Key = Self;

    unsafe fn from_sockaddr(addr: *const sockaddr_in6) -> Self {
        let field = addr
            .wrapping_byte_add(offset_of!(sockaddr_in6, sin6_addr))
            .cast::<in6_addr>();
        // SAFETY: `ptr::read_unaligned`: `sin6_addr` lies within the readable
        // `sockaddr_in6` (this function's contract), is initialized, and an
        // `in6_addr` is a `[u8; 16]`, valid for any initialized bytes.
        let addr = unsafe { field.read_unaligned() };
        Self::from(addr.s6_addr)
    }

    fn clone_key(&self) -> Self::Key {
        *self
    }
}

struct AddrInfoGuard(
    // Safety invariant: null, or a list returned by getaddrinfo(3) that is
    // not freed yet and is owned by this guard.
    *mut addrinfo,
);

impl Drop for AddrInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: freeaddrinfo(3) frees a list returned by getaddrinfo(3):
            // the field invariant, and the guard drops once.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}
