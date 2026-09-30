use std::ffi::CStr;
use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    time::Duration,
};

use ahash::{HashSet, HashSetExt as _};
use libc::{AF_INET, AF_INET6, SOCK_STREAM, addrinfo};
use rama_core::{
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, LookupEvent, NativeConfig, dns_name_from_domain};
use crate::client::limit::deadline_after;

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    lookup_address_stream(
        domain,
        timeout,
        native,
        AF_INET,
        lookup_addresses_impl::<Ipv4Addr>,
    )
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    lookup_address_stream(
        domain,
        timeout,
        native,
        AF_INET6,
        lookup_addresses_impl::<Ipv6Addr>,
    )
}

fn lookup_address_stream<T, F>(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
    family: libc::c_int,
    lookup: F,
) -> impl Stream<Item = Result<LookupEvent<T>, BoxError>> + Send
where
    T: Send + 'static + std::fmt::Debug,
    F: FnOnce(
            &Domain,
            libc::c_int,
            &mpsc::Sender<Result<LookupEvent<T>, BoxError>>,
        ) -> Result<(), BoxError>
        + Send
        + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, family, "dns::linux: getaddrinfo query");

        let deadline = deadline_after(timeout);
        let (tx, mut rx) = mpsc::channel(8);
        let task = native.limit.spawn_blocking(deadline, move |budget| {
            if budget.is_zero() {
                return Err(LinuxDnsResolverError::timeout(timeout).into());
            }
            lookup(&domain, family, &tx)
        });
        let Some(join) = task.await else {
            tracing::debug!("linux::getaddrinfo: no native lookup slot before the deadline");
            yielder
                .yield_item(Err(LinuxDnsResolverError::timeout(timeout).into()))
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
                        .yield_item(Err(LinuxDnsResolverError::timeout(timeout).into()))
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
    family: libc::c_int,
    tx: &mpsc::Sender<Result<LookupEvent<T>, BoxError>>,
) -> Result<(), BoxError>
where
    T: FromSockAddr,
{
    let name = dns_name_from_domain(domain.as_str())?;

    let hints = addrinfo {
        ai_flags: libc::AI_ADDRCONFIG,
        ai_family: family,
        ai_socktype: SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };

    let mut result: *mut addrinfo = ptr::null_mut();
    let status = unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut result) };
    if status != 0 {
        // SAFETY: `gai_strerror` returns a static NUL-terminated message.
        let message = unsafe { libc::gai_strerror(status) };
        let message = unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned();
        return Err(
            LinuxDnsResolverError::message(format!("getaddrinfo failed: {message}")).into(),
        );
    }

    let _guard = AddrInfoGuard(result);
    let mut seen = HashSet::new();
    let mut current = result;

    while !current.is_null() {
        let current_ref = unsafe { &*current };
        if current_ref.ai_family == family
            && !current_ref.ai_addr.is_null()
            && (current_ref.ai_addrlen as usize) >= T::sockaddr_len()
        {
            let addr = unsafe { T::from_sockaddr(current_ref.ai_addr.cast()) };
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

trait FromSockAddr: Sized {
    type Key: Eq + std::hash::Hash;

    unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Self;
    fn sockaddr_len() -> usize;
    fn clone_key(&self) -> Self::Key;
}

impl FromSockAddr for Ipv4Addr {
    type Key = Self;

    unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Self {
        let addr = unsafe { &*addr.cast::<libc::sockaddr_in>() };
        Self::from(addr.sin_addr.s_addr.to_ne_bytes())
    }

    fn sockaddr_len() -> usize {
        size_of::<libc::sockaddr_in>()
    }

    fn clone_key(&self) -> Self::Key {
        *self
    }
}

impl FromSockAddr for Ipv6Addr {
    type Key = Self;

    unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Self {
        let addr = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
        Self::from(addr.sin6_addr.s6_addr)
    }

    fn sockaddr_len() -> usize {
        size_of::<libc::sockaddr_in6>()
    }

    fn clone_key(&self) -> Self::Key {
        *self
    }
}

struct AddrInfoGuard(*mut addrinfo);

impl Drop for AddrInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                libc::freeaddrinfo(self.0);
            }
        }
    }
}
