use std::collections::HashSet;
use std::ffi::CStr;
use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    time::Duration,
};

use libc::{AF_INET, AF_INET6, SOCK_STREAM, addrinfo};
use rama_core::{
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    stream::{StreamExt, wrappers::ReceiverStream},
    telemetry::tracing,
};
use rama_net::address::Domain;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, dns_name_from_domain};

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send {
    lookup_address_stream(domain, timeout, AF_INET, lookup_ipv4_impl)
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send {
    lookup_address_stream(domain, timeout, AF_INET6, lookup_ipv6_impl)
}

fn lookup_address_stream<T, F>(
    domain: Domain,
    timeout: Duration,
    family: libc::c_int,
    lookup: F,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Send + 'static + std::fmt::Debug,
    F: FnOnce(Domain, libc::c_int, mpsc::Sender<Result<T, BoxError>>) -> Result<(), BoxError>
        + Send
        + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, family, "dns::linux: getaddrinfo query");

        let (tx, rx) = mpsc::channel(8);
        let join = tokio::task::spawn_blocking(move || lookup(domain, family, tx));

        let mut stream = std::pin::pin!(ReceiverStream::new(rx).timeout(timeout));

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => yielder.yield_item(item).await,
                Err(err) => {
                    tracing::debug!(
                        %err,
                        "linux::getaddrinfo: item failed to resolve on time: return timeout error",
                    );
                    // `res_nquery` is a blocking libc call, so timing out here only stops
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

fn lookup_ipv4_impl(
    domain: Domain,
    family: libc::c_int,
    tx: mpsc::Sender<Result<Ipv4Addr, BoxError>>,
) -> Result<(), BoxError> {
    lookup_addresses_impl::<Ipv4Addr>(domain, family, tx)
}

fn lookup_ipv6_impl(
    domain: Domain,
    family: libc::c_int,
    tx: mpsc::Sender<Result<Ipv6Addr, BoxError>>,
) -> Result<(), BoxError> {
    lookup_addresses_impl::<Ipv6Addr>(domain, family, tx)
}

fn lookup_addresses_impl<T>(
    domain: Domain,
    family: libc::c_int,
    tx: mpsc::Sender<Result<T, BoxError>>,
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
        let message = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }
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
            if seen.insert(addr.clone_key()) && tx.blocking_send(Ok(addr)).is_err() {
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
    type Key = Ipv4Addr;

    unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Self {
        let addr = unsafe { &*addr.cast::<libc::sockaddr_in>() };
        Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())
    }

    fn sockaddr_len() -> usize {
        size_of::<libc::sockaddr_in>()
    }

    fn clone_key(&self) -> Self::Key {
        *self
    }
}

impl FromSockAddr for Ipv6Addr {
    type Key = Ipv6Addr;

    unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Self {
        let addr = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
        Ipv6Addr::from(addr.sin6_addr.s6_addr)
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
